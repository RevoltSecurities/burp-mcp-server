package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionProfile
import com.revoltsecurities.burpmcp.output.MessageRegistry
import com.revoltsecurities.burpmcp.output.PageEnvelope
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

// A BurpActions fake that captures the exact raw request(s) sent and returns a configurable exchange.
private class CapturingActions(
    private val makeResponse: (String) -> SentExchange = { raw ->
        SentExchange(200, "text/html", raw.toByteArray(), "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok".toByteArray())
    },
) : BurpActions {
    var lastRaw: String? = null
    val sentRaws = mutableListOf<String>()
    var bcheckOutcome = ImportOutcome("LOADED_WITHOUT_ERRORS", ok = true)

    override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String): SentExchange {
        lastRaw = raw; sentRaws += raw; return makeResponse(raw)
    }
    override fun sendParallel(requests: List<RawTarget>, mode: String): List<SentExchange> =
        requests.map { sentRaws += it.raw; makeResponse(it.raw) }
    override fun sendToRepeater(raw: String, host: String, port: Int, secure: Boolean, name: String?) {}
    override fun sendToIntruder(raw: String, host: String, port: Int, secure: Boolean, name: String?) {}
    override fun includeInScope(url: String) {}
    override fun excludeFromScope(url: String) {}
    override fun setIntercept(enabled: Boolean) {}
    override fun isInterceptEnabled() = false
    override fun cookies() = emptyList<CookieDTO>()
    override fun setCookie(name: String, value: String, domain: String, path: String?, expiresEpochSec: Long?) {}
    override fun createIssue(issue: NewIssue) = true
    override fun addToSiteMap(raw: String, host: String, port: Int, secure: Boolean, responseRaw: String?) {}
    override fun managedEngineAvailable() = false
    override fun importBCheck(script: String, enabled: Boolean) = bcheckOutcome
}

class SessionInjectorTest {

    @Test
    fun `adds Host header when missing but not when present`() {
        val out = SessionInjector.apply("GET / HTTP/1.1\r\n\r\n", SessionProfile(), "ex.com")
        assertTrue(out.contains("Host: ex.com"))

        val keep = SessionInjector.apply("GET / HTTP/1.1\r\nHost: real\r\n\r\n", SessionProfile(), "ex.com")
        assertEquals(1, Regex("(?i)^Host:", RegexOption.MULTILINE).findAll(keep).count())
        assertTrue(keep.contains("Host: real"))
    }

    @Test
    fun `hostOverride replaces the Host header`() {
        val out = SessionInjector.apply("GET / HTTP/1.1\r\nHost: old\r\n\r\n", SessionProfile(hostOverride = "vhost"), "ex.com")
        assertTrue(out.contains("Host: vhost"))
        assertFalse(out.contains("Host: old"))
    }

    @Test
    fun `headers are added and replaced case-insensitively`() {
        val raw = "GET / HTTP/1.1\r\nHost: h\r\nauthorization: old\r\n\r\n"
        val out = SessionInjector.apply(raw, SessionProfile(headers = mapOf("Authorization" to "Bearer new", "X-K" to "v")), "h")
        assertTrue(out.contains("Authorization: Bearer new"))
        assertFalse(out.contains("old"))
        assertTrue(out.contains("X-K: v"))
    }

    @Test
    fun `cookies merge into one Cookie header overriding same-named`() {
        val raw = "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1; b=2\r\n\r\n"
        val out = SessionInjector.apply(raw, SessionProfile(cookies = mapOf("b" to "9", "c" to "3")), "h")
        val cookieLine = out.lines().first { it.startsWith("Cookie:") }
        assertEquals("Cookie: a=1; b=9; c=3", cookieLine)
    }

    @Test
    fun `collapses multiple Cookie headers into one merged header`() {
        val raw = "GET / HTTP/1.1\r\nHost: h\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"
        val out = SessionInjector.apply(raw, SessionProfile(cookies = mapOf("c" to "3")), "h")
        assertEquals(1, out.lines().count { it.startsWith("Cookie:") })
        val cookieLine = out.lines().first { it.startsWith("Cookie:") }
        assertEquals("Cookie: a=1; b=2; c=3", cookieLine)
    }

    @Test
    fun `creates a Cookie header when none exists and preserves the body`() {
        val raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"k\":1}"
        val out = SessionInjector.apply(raw, SessionProfile(cookies = mapOf("s" to "t")), "h")
        assertTrue(out.contains("Cookie: s=t"))
        assertTrue(out.endsWith("{\"k\":1}"))
    }

    @Test
    fun `empty profile with Host present is byte-exact (preserves smuggling payloads)`() {
        val crafted = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
        assertEquals(crafted, SessionInjector.apply(crafted, SessionProfile(), "h"))
    }

    @Test
    fun `merge lets override win`() {
        val base = SessionProfile(cookies = mapOf("a" to "1"), headers = mapOf("H" to "b"))
        val merged = base.mergedWith(SessionProfile(cookies = mapOf("a" to "2"), headers = mapOf("H" to "o")))
        assertEquals("2", merged.cookies["a"])
        assertEquals("o", merged.headers["H"])
    }
}

class CollaboratorKeyStoreTest {

    @Test
    fun `remembers keys without duplicates and lists them in order`() {
        val backing = HashMap<String, String>()
        val store = CollaboratorKeyStore({ backing[it] }, { k, v -> backing[k] = v })
        store.remember("k1"); store.remember("k2"); store.remember("k1")
        assertEquals(listOf("k1", "k2"), store.all())
    }

    @Test
    fun `empty store returns empty list`() {
        val store = CollaboratorKeyStore({ null }, { _, _ -> })
        assertTrue(store.all().isEmpty())
    }
}

class HttpMessageReResolveTest {

    private fun exchange(i: Int) = HttpExchange(
        index = i, method = "GET", url = "https://a.com/p$i", host = "a.com", statusCode = 200,
        mimeType = "text/html", requestLength = 5, responseLength = 7, notes = null, inScope = true,
        requestBytes = { "GET /p$i HTTP/1.1\r\nHost: a.com\r\n\r\n".toByteArray() },
        responseBytes = { "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody-$i".toByteArray() },
    )

    private val source = object : BurpDataSource {
        override fun proxyHistory() = listOf(exchange(5)) // index 5, NOT list position 0
        override fun webSocketHistory() = listOf(
            WebSocketRecord(3, "wss://a.com/ws", "a.com", "CLIENT_TO_SERVER", 4, { "ping".toByteArray() }),
        )
        override fun siteMap() = emptyList<SiteMapNode>()
        override fun issues() = emptyList<IssueRecord>()
        override fun isInScope(url: String) = true
        override fun burpVersion() = "x"; override fun burpEdition() = "PROFESSIONAL"; override fun isProfessional() = true
    }

    private val cfg = ToolConfig(50, 100, 96_000, 8_192, 65_536)

    private fun callGet(registry: MessageRegistry, id: String, section: String = "body") = runBlocking {
        HttpMessageTool.build(registry, cfg, source).handler(
            Args(buildJsonObject { put("id", JsonPrimitive(id)); put("part", JsonPrimitive("response")); put("section", JsonPrimitive(section)) }),
        )
    }

    @Test
    fun `re-resolves a proxy id from source when not in the registry`() {
        val registry = MessageRegistry() // empty — simulate eviction / fresh session
        val res = callGet(registry, "ph:5")
        val msg = Results.json.decodeFromJsonElement(HttpMessageResult.serializer(), res.structuredContent!!)
        assertEquals("body-5", msg.content)
        assertNotNull(registry.get("ph:5")) // and it got cached
    }

    @Test
    fun `re-resolves a websocket payload by ws id`() {
        val res = callGet(MessageRegistry(), "ws:3")
        val msg = Results.json.decodeFromJsonElement(HttpMessageResult.serializer(), res.structuredContent!!)
        assertEquals("ping", msg.content)
    }

    @Test
    fun `session-only ids give a clear expiry error, not a scope failure`() {
        val res = callGet(MessageRegistry(), "send:9")
        assertTrue(res.isError == true)
        assertTrue((res.content.first() as io.modelcontextprotocol.kotlin.sdk.types.TextContent).text!!.contains("session-only"))
    }
}

class ReadFilterFixesTest {

    private fun ex(i: Int, len: Int, body: String) = HttpExchange(
        index = i, method = "GET", url = "https://a.com/p$i", host = "a.com", statusCode = 200,
        mimeType = "text/html", requestLength = 5, responseLength = len, notes = null, inScope = true,
        requestBytes = { "GET /p$i HTTP/1.1\r\nHost: a.com\r\n\r\n".toByteArray() },
        responseBytes = { "HTTP/1.1 200 OK\r\n\r\n$body".toByteArray() },
    )

    private val source = object : BurpDataSource {
        override fun proxyHistory() = listOf(ex(0, 3, "abc"), ex(1, 100, "SECRET token here"), ex(2, 50, "nothing"))
        override fun webSocketHistory() = listOf(
            WebSocketRecord(0, "wss://a.com/ws", "a.com", "CLIENT_TO_SERVER", 5, { "hello".toByteArray() }),
            WebSocketRecord(1, "wss://a.com/ws", "a.com", "SERVER_TO_CLIENT", 5, { "world".toByteArray() }),
        )
        override fun siteMap() = emptyList<SiteMapNode>()
        override fun issues() = emptyList<IssueRecord>()
        override fun isInScope(url: String) = true
        override fun burpVersion() = "x"; override fun burpEdition() = "PROFESSIONAL"; override fun isProfessional() = true
    }

    private val registry = MessageRegistry()
    private val cfg = ToolConfig(50, 100, 96_000, 8_192, 65_536)
    private val tools = ReadTools(source, registry, cfg).build().associateBy { it.id }

    private fun call(id: String, args: Map<String, Any?>) = runBlocking {
        tools.getValue(id).handler(
            Args(buildJsonObject {
                args.forEach { (k, v) ->
                    when (v) { is String -> put(k, JsonPrimitive(v)); is Int -> put(k, JsonPrimitive(v)); is Boolean -> put(k, JsonPrimitive(v)); else -> {} }
                }
            }),
        )
    }

    @Test
    fun `minResponseLength filters small responses`() {
        val env = Results.json.decodeFromJsonElement(
            PageEnvelope.serializer(ProxyHistoryRow.serializer()),
            call("get_proxy_http_history", mapOf("minResponseLength" to 10)).structuredContent!!,
        )
        assertEquals(setOf(1, 2), env.items.map { it.index }.toSet())
    }

    @Test
    fun `responseContains searches the response body`() {
        val env = Results.json.decodeFromJsonElement(
            PageEnvelope.serializer(ProxyHistoryRow.serializer()),
            call("get_proxy_http_history", mapOf("responseContains" to "secret")).structuredContent!!,
        )
        assertEquals(listOf(1), env.items.map { it.index })
    }

    @Test
    fun `ws direction filter and payload contains, row id resolvable`() {
        val env = Results.json.decodeFromJsonElement(
            PageEnvelope.serializer(WsRow.serializer()),
            call("get_proxy_ws_history", mapOf("direction" to "server_to_client")).structuredContent!!,
        )
        assertEquals(1, env.items.size)
        assertEquals("ws:1", env.items.first().id)

        val contains = Results.json.decodeFromJsonElement(
            PageEnvelope.serializer(WsRow.serializer()),
            call("get_proxy_ws_history", mapOf("contains" to "hello")).structuredContent!!,
        )
        assertEquals(listOf(0), contains.items.map { it.index })
        assertNotNull(registry.get("ws:0")) // listing registered the payload handle
    }
}

class SendSessionInjectionTest {

    private val registry = MessageRegistry()
    private val guard = ScopeGuard({ false }, { true })

    private fun convenience(actions: BurpActions, profile: SessionProfile = SessionProfile()) =
        ConvenienceTools(actions, registry, guard) { profile }.build().associateBy { it.id }

    @Test
    fun `http_send_analyze injects the stored profile and per-call headers`() {
        val actions = CapturingActions()
        val tool = convenience(actions, SessionProfile(cookies = mapOf("sess" to "abc")))["http_send_analyze"]!!
        runBlocking {
            tool.handler(Args(buildJsonObject {
                put("content", JsonPrimitive("GET /u/1 HTTP/1.1\r\nHost: t\r\n\r\n"))
                put("host", JsonPrimitive("t.com"))
                putJsonArray("headers") { add("Authorization: Bearer X") }
            }))
        }
        assertTrue(actions.lastRaw!!.contains("Cookie: sess=abc"))
        assertTrue(actions.lastRaw!!.contains("Authorization: Bearer X"))
    }

    @Test
    fun `http_send_compare surfaces the error when sends get no response`() {
        val actions = CapturingActions { raw -> SentExchange(null, null, raw.toByteArray(), null, "no response (timeout)") }
        val tool = convenience(actions)["http_send_compare"]!!
        val res = runBlocking {
            tool.handler(Args(buildJsonObject {
                put("contentA", JsonPrimitive("GET /id/1 HTTP/1.1\r\nHost: t\r\n\r\n"))
                put("contentB", JsonPrimitive("GET /id/2 HTTP/1.1\r\nHost: t\r\n\r\n"))
                put("host", JsonPrimitive("t.com"))
            }))
        }
        val r = Results.json.decodeFromJsonElement(SendCompareResult.serializer(), res.structuredContent!!)
        assertEquals("no response (timeout)", r.errorA)
        assertEquals("no response (timeout)", r.errorB)
        assertTrue(r.note!!.contains("no response", ignoreCase = true))
    }
}

class BcheckSurfaceTest {

    @Test
    fun `bcheck_import returns an error result when the script has errors`() {
        val actions = CapturingActions().apply {
            bcheckOutcome = ImportOutcome("LOADED_WITH_ERRORS", listOf("line 3: unexpected token"), ok = false)
        }
        val tool = ExtraActionTools(actions, ScopeGuard({ false }, { true })).build().first { it.id == "bcheck_import" }
        val res = runBlocking { tool.handler(Args(buildJsonObject { put("script", JsonPrimitive("metadata:\n  language: v1-beta")) })) }
        assertTrue(res.isError == true)
        val outcome = Results.json.decodeFromJsonElement(ImportOutcome.serializer(), res.structuredContent!!)
        assertFalse(outcome.ok)
        assertTrue(outcome.errors.first().contains("unexpected token"))
    }

    @Test
    fun `bcheck_import succeeds cleanly without errors`() {
        val actions = CapturingActions() // default ok outcome
        val tool = ExtraActionTools(actions, ScopeGuard({ false }, { true })).build().first { it.id == "bcheck_import" }
        val res = runBlocking { tool.handler(Args(buildJsonObject { put("script", JsonPrimitive("metadata:\n  language: v2-beta")) })) }
        assertFalse(res.isError == true)
    }
}

class SessionToolsTest {

    private var stored = SessionProfile()
    private fun tools(unsafe: Boolean) = SessionTools({ stored }, { stored = it }, { unsafe }).build().associateBy { it.id }

    private fun call(id: String, unsafe: Boolean = false, build: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit = {}) =
        runBlocking { tools(unsafe).getValue(id).handler(Args(buildJsonObject(build))) }

    @Test
    fun `session_set merges and session_clear empties`() {
        call("session_set") { putJsonArray("cookies") { add("a=1") }; putJsonArray("headers") { add("Authorization: Bearer x") } }
        assertEquals("1", stored.cookies["a"])
        assertEquals("Bearer x", stored.headers["Authorization"])
        call("session_set") { putJsonArray("cookies") { add("b=2") } } // merge, not replace
        assertEquals("1", stored.cookies["a"]); assertEquals("2", stored.cookies["b"])
        call("session_clear")
        assertTrue(stored.isEmpty)
    }

    @Test
    fun `session_set replace drops previous values`() {
        call("session_set") { putJsonArray("cookies") { add("a=1") } }
        call("session_set") { putJsonArray("cookies") { add("b=2") }; put("replace", JsonPrimitive(true)) }
        assertNull(stored.cookies["a"]); assertEquals("2", stored.cookies["b"])
    }

    @Test
    fun `session_get redacts unless unsafe is on`() {
        stored = SessionProfile(cookies = mapOf("s" to "secret"))
        val redacted = Results.json.decodeFromJsonElement(SessionProfileView.serializer(), call("session_get").structuredContent!!)
        assertEquals("[REDACTED]", redacted.cookies["s"]); assertTrue(redacted.redacted)
        val revealed = Results.json.decodeFromJsonElement(SessionProfileView.serializer(), call("session_get", unsafe = true).structuredContent!!)
        assertEquals("secret", revealed.cookies["s"]); assertFalse(revealed.redacted)
    }

    @Test
    fun `session_set is mutating, session_get is not`() {
        val t = tools(false)
        assertTrue(t.getValue("session_set").mutating)
        assertFalse(t.getValue("session_get").mutating)
        assertTrue(t.getValue("session_clear").mutating)
    }
}
