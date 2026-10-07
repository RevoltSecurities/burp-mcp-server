package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionLogin
import com.revoltsecurities.burpmcp.config.SessionProfile
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SessionRefresherTest {

    @Test
    fun `extractToken uses capture group 1`() {
        val resp = "HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"TOK123\",\"ttl\":60}"
        assertEquals("TOK123", SessionRefresher.extractToken(resp, "\"access_token\":\"([^\"]+)\""))
    }

    @Test
    fun `extractToken falls back to whole match with no group`() {
        assertEquals("abc123", SessionRefresher.extractToken("x=abc123;", "[a-z]+[0-9]+"))
    }

    @Test
    fun `extractToken returns null on no match or blank regex`() {
        assertNull(SessionRefresher.extractToken("nothing here", "token=([0-9]+)"))
        assertNull(SessionRefresher.extractToken("x", ""))
    }

    @Test
    fun `profileDelta formats header with template and cookie without`() {
        val h = SessionRefresher.profileDelta("TOK", SessionLogin(location = "header", name = "Authorization", template = "Bearer {token}"))
        assertEquals("Bearer TOK", h.headers["Authorization"])
        val c = SessionRefresher.profileDelta("TOK", SessionLogin(location = "cookie", name = "sid", template = "{token}"))
        assertEquals("TOK", c.cookies["sid"])
    }

    @Test
    fun `shouldTrigger honors configured statuses with 401 or 403 default`() {
        assertTrue(SessionRefresher.shouldTrigger(401, emptyList()))
        assertTrue(SessionRefresher.shouldTrigger(403, emptyList()))
        assertFalse(SessionRefresher.shouldTrigger(500, emptyList()))
        assertTrue(SessionRefresher.shouldTrigger(419, listOf(419)))
        assertFalse(SessionRefresher.shouldTrigger(401, listOf(419)))
    }
}

class SessionRefreshServiceTest {

    private val goodLogin = SessionLogin(
        enabled = true, request = "POST /login HTTP/1.1\r\nHost: t.com\r\n\r\nu=a&p=b", host = "t.com",
        extractRegex = "\"access_token\":\"([^\"]+)\"", location = "header", name = "Authorization", template = "Bearer {token}",
    )

    private fun service(
        login: () -> SessionLogin,
        profileHolder: Array<SessionProfile>,
        now: () -> Long = { 1000L },
        scopeAllows: (String, Int, Boolean) -> Boolean = { _, _, _ -> true },
        send: (String, String, Int, Boolean) -> SentExchange,
    ) = SessionRefreshService(
        send = send, loginProvider = login, currentProfile = { profileHolder[0] },
        updateProfile = { profileHolder[0] = it }, scopeAllows = scopeAllows, minIntervalMs = 5_000, clock = now,
    )

    private fun ok(body: String): (String, String, Int, Boolean) -> SentExchange =
        { raw, _, _, _ -> SentExchange(200, "application/json", raw.toByteArray(), "HTTP/1.1 200 OK\r\n\r\n$body".toByteArray()) }

    @Test
    fun `refresh replays login and rotates the token into the profile`() {
        val profile = arrayOf(SessionProfile(cookies = mapOf("keep" to "1")))
        val svc = service({ goodLogin }, profile, send = ok("{\"access_token\":\"TOK999\"}"))
        val out = svc.refresh(force = true)
        assertTrue(out.ok); assertEquals("refreshed", out.status); assertEquals(6, out.tokenLength)
        assertEquals("Bearer TOK999", profile[0].headers["Authorization"])
        assertEquals("1", profile[0].cookies["keep"]) // existing profile preserved
    }

    @Test
    fun `not configured leaves the profile untouched`() {
        val profile = arrayOf(SessionProfile())
        val svc = service({ SessionLogin() }, profile, send = ok("{\"access_token\":\"x\"}"))
        assertEquals("not_configured", svc.refresh(force = true).status)
        assertTrue(profile[0].isEmpty)
    }

    @Test
    fun `a failed login does not mutate the profile`() {
        val profile = arrayOf(SessionProfile())
        val svc = service({ goodLogin }, profile) { raw, _, _, _ -> SentExchange(null, null, raw.toByteArray(), null, "connection refused") }
        val out = svc.refresh(force = true)
        assertFalse(out.ok); assertEquals("failed", out.status); assertTrue(profile[0].isEmpty)
    }

    @Test
    fun `regex that matches nothing is reported and leaves the profile untouched`() {
        val profile = arrayOf(SessionProfile())
        val svc = service({ goodLogin }, profile, send = ok("{\"no_token\":true}"))
        val out = svc.refresh(force = true)
        assertFalse(out.ok); assertTrue(out.note.contains("matched no token"))
        assertTrue(profile[0].isEmpty)
    }

    @Test
    fun `status-triggered refresh is debounced`() {
        val profile = arrayOf(SessionProfile())
        var now = 1_000L
        val svc = service({ goodLogin }, profile, now = { now }, send = ok("{\"access_token\":\"T\"}"))
        assertTrue(svc.refresh(force = true).ok) // lastRefresh = 1000
        now = 2_000L
        assertEquals("skipped", svc.maybeRefreshOnStatus(401).status) // within 5s window
        now = 7_000L
        assertTrue(svc.maybeRefreshOnStatus(401).ok) // window elapsed
    }

    @Test
    fun `non-trigger status does not refresh`() {
        val profile = arrayOf(SessionProfile())
        val svc = service({ goodLogin }, profile, send = ok("{\"access_token\":\"T\"}"))
        assertEquals("skipped", svc.maybeRefreshOnStatus(200).status)
    }

    @Test
    fun `out-of-scope login host is refused and sends nothing`() {
        val profile = arrayOf(SessionProfile())
        var sent = false
        val svc = service({ goodLogin }, profile, scopeAllows = { _, _, _ -> false }) { raw, _, _, _ -> sent = true; SentExchange(200, null, raw.toByteArray(), "x".toByteArray()) }
        val out = svc.refresh(force = true)
        assertFalse(out.ok); assertEquals("failed", out.status); assertTrue(out.note.contains("out of scope"))
        assertFalse(sent); assertTrue(profile[0].isEmpty)
    }

    @Test
    fun `a failed login still debounces (does not re-fire on every trigger)`() {
        val profile = arrayOf(SessionProfile())
        var now = 1_000L
        var calls = 0
        val svc = service({ goodLogin }, profile, now = { now }) { raw, _, _, _ -> calls++; SentExchange(null, null, raw.toByteArray(), null, "boom") }
        assertEquals("failed", svc.refresh(force = true).status) // attempt 1 (now=1000)
        now = 2_000L
        assertEquals("skipped", svc.maybeRefreshOnStatus(401).status) // within window → no new send
        assertEquals(1, calls)
        now = 7_000L
        svc.maybeRefreshOnStatus(401) // window elapsed → sends again
        assertEquals(2, calls)
    }
}

class SessionLoginToolsTest {

    private var login = SessionLogin()
    private var profile = SessionProfile()
    private val svc = SessionRefreshService(
        send = { raw, _, _, _ -> SentExchange(200, "application/json", raw.toByteArray(), "HTTP/1.1 200 OK\r\n\r\n{\"access_token\":\"FRESH\"}".toByteArray()) },
        loginProvider = { login }, currentProfile = { profile }, updateProfile = { profile = it },
    )

    private fun tools(unsafe: Boolean) = SessionTools(
        profileProvider = { profile }, updateProfile = { profile = it }, unsafeEnabled = { unsafe },
        loginProvider = { login }, updateLogin = { login = it }, refreshService = svc,
    ).build().associateBy { it.id }

    private fun call(id: String, unsafe: Boolean = false, build: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit = {}) =
        runBlocking { tools(unsafe).getValue(id).handler(Args(buildJsonObject(build))) }

    @Test
    fun `session_login_set stores config and session_login_get redacts the request`() {
        call("session_login_set") {
            put("request", JsonPrimitive("POST /login HTTP/1.1\r\nHost: t.com\r\n\r\nu=a"))
            put("host", JsonPrimitive("t.com"))
            put("extractRegex", JsonPrimitive("\"access_token\":\"([^\"]+)\""))
            put("template", JsonPrimitive("Bearer {token}"))
            put("triggerStatuses", JsonPrimitive("401, 419"))
        }
        assertTrue(login.enabled); assertEquals("t.com", login.host); assertEquals(listOf(401, 419), login.triggerStatuses)

        val redacted = Results.json.decodeFromJsonElement(SessionLoginView.serializer(), call("session_login_get").structuredContent!!)
        assertTrue(redacted.redacted); assertTrue(redacted.request.startsWith("[REDACTED"))
        val revealed = Results.json.decodeFromJsonElement(SessionLoginView.serializer(), call("session_login_get", unsafe = true).structuredContent!!)
        assertTrue(revealed.request.startsWith("POST /login"))
    }

    @Test
    fun `session_login_now refreshes and rotates the token`() {
        login = SessionLogin(enabled = true, request = "POST /login HTTP/1.1\r\nHost: t.com\r\n\r\nu=a", host = "t.com", extractRegex = "\"access_token\":\"([^\"]+)\"", template = "Bearer {token}")
        val res = call("session_login_now")
        val out = Results.json.decodeFromJsonElement(SessionLoginNowResult.serializer(), res.structuredContent!!)
        assertTrue(out.refresh.ok)
        assertEquals("Bearer FRESH", profile.headers["Authorization"])
    }

    @Test
    fun `session_login_set rejects an invalid regex`() {
        val before = login
        val res = call("session_login_set") {
            put("request", JsonPrimitive("POST /login HTTP/1.1\r\nHost: t\r\n\r\n"))
            put("host", JsonPrimitive("t.com"))
            put("extractRegex", JsonPrimitive("(unclosed["))
        }
        assertTrue(res.isError == true)
        assertEquals(before, login) // not stored
    }

    @Test
    fun `session_login_clear disables refresh`() {
        login = SessionLogin(enabled = true, request = "x", host = "t.com", extractRegex = "y")
        call("session_login_clear")
        assertFalse(login.enabled); assertFalse(login.isConfigured)
    }

    @Test
    fun `login tools mutating flags`() {
        val t = tools(false)
        assertTrue(t.getValue("session_login_set").mutating)
        assertFalse(t.getValue("session_login_get").mutating)
        assertTrue(t.getValue("session_login_now").mutating)
    }
}
