package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PayloadEngineTest {

    private val tpl = "GET /u/§1§/p/§x§ HTTP/1.1\r\nHost: t\r\n\r\n"

    @Test
    fun `parse finds positions and base values`() {
        val t = PayloadEngine.parse(tpl)
        assertEquals(2, t.positionCount)
        assertEquals(listOf("1", "x"), t.baseValues)
        assertEquals("GET /u/A/p/B HTTP/1.1\r\nHost: t\r\n\r\n", t.render(listOf("A", "B")))
    }

    @Test
    fun `unbalanced markers yield no positions`() {
        assertEquals(0, PayloadEngine.parse("GET /§oops HTTP/1.1").positionCount)
    }

    @Test
    fun `sniper fuzzes one position at a time keeping base values`() {
        val g = PayloadEngine.generate(tpl, "sniper", listOf(listOf("a", "b")), 100)
        assertEquals(4, g.size) // 2 positions x 2 payloads
        // first two fuzz position 0 (base "x" kept at position 1)
        assertTrue(g[0].request.contains("/u/a/p/x"))
        assertTrue(g[1].request.contains("/u/b/p/x"))
        assertTrue(g[2].request.contains("/u/1/p/a"))
    }

    @Test
    fun `pitchfork iterates sets in lockstep`() {
        val g = PayloadEngine.generate(tpl, "pitchfork", listOf(listOf("a", "b"), listOf("1", "2")), 100)
        assertEquals(2, g.size)
        assertTrue(g[0].request.contains("/u/a/p/1"))
        assertTrue(g[1].request.contains("/u/b/p/2"))
    }

    @Test
    fun `clusterbomb is the cartesian product`() {
        val g = PayloadEngine.generate(tpl, "clusterbomb", listOf(listOf("a", "b"), listOf("1", "2")), 100)
        assertEquals(4, g.size)
        assertEquals(setOf("/u/a/p/1", "/u/a/p/2", "/u/b/p/1", "/u/b/p/2"), g.map { it.payloads.let { p -> "/u/${p[0]}/p/${p[1]}" } }.toSet())
    }

    @Test
    fun `maxRequests caps output`() {
        val g = PayloadEngine.generate(tpl, "clusterbomb", listOf(listOf("a", "b", "c"), listOf("1", "2", "3")), 5)
        assertEquals(5, g.size)
    }
}

private class P10Actions : BurpActions {
    var organizerSent = false; var wsMsg: String? = null; var bcheck: String? = null
    val store = linkedMapOf<String, String>(); var taskState = "RUNNING"
    override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String) =
        SentExchange(200, "text/html", raw.toByteArray(), "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhi ${raw.substringAfter("/u/").substringBefore("/")}".toByteArray())
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
    override fun sendParallel(requests: List<RawTarget>, mode: String) =
        requests.mapIndexed { i, r -> SentExchange(if (i == 0) 302 else 200, "text/html", r.raw.toByteArray(), "body$i".toByteArray()) }
    override fun managedEngineAvailable() = false
    override fun sendToOrganizer(raw: String, host: String, port: Int, secure: Boolean) { organizerSent = true }
    override fun organizerItems() = listOf(OrganizerItemDTO(1, "NEW"))
    override fun wsSend(host: String, path: String, secure: Boolean, message: String, waitMs: Long): WsSendResult {
        wsMsg = message; return WsSendResult(true, 101, listOf("echo:$message"), "ok")
    }
    override fun importBCheck(script: String, enabled: Boolean): ImportOutcome { bcheck = script; return ImportOutcome("LOADED") }
    override fun importBambda(script: String) = ImportOutcome("LOADED")
    override fun exportProjectOptions() = "{\"proxy\":true}"
    override fun importProjectOptions(json: String) {}
    override fun exportUserOptions() = "{\"user\":true}"
    override fun importUserOptions(json: String) {}
    override fun taskEngineGet() = taskState
    override fun taskEngineSet(state: String): String { taskState = state.uppercase(); return taskState }
    override fun persistenceGet(key: String) = store[key]
    override fun persistenceSet(key: String, value: String) { store[key] = value }
    override fun persistenceKeys() = store.keys.toList()
}

class Phase10ToolsTest {

    private val registry = MessageRegistry()
    private val guard = ScopeGuard({ false }, { true })
    private val actions = P10Actions()

    private fun specs() = (ConvenienceTools(actions, registry, guard).build() +
        IntruderTools(actions, registry, guard).build() +
        ExtraActionTools(actions, guard).build() +
        ControlTools(actions).build()).associateBy { it.id }

    private fun call(id: String, build: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit) =
        runBlocking { specs().getValue(id).handler(Args(buildJsonObject(build))) }

    @Test
    fun `http_send_analyze returns status + reflected + handle`() {
        val res = call("http_send_analyze") {
            put("content", JsonPrimitive("GET /u/alice HTTP/1.1\r\nHost: t\r\n\r\n?name=alice"))
            put("host", JsonPrimitive("t.com"))
        }
        val r = Results.json.decodeFromJsonElement(SendAnalyzeResult.serializer(), res.structuredContent!!)
        assertEquals(200, r.status)
        assertTrue(registry.get(r.id) != null)
    }

    @Test
    fun `intruder_attack sniper fires per payload and flags divergence`() {
        val res = call("intruder_attack") {
            put("template", JsonPrimitive("GET /u/§1§ HTTP/1.1\r\nHost: t\r\n\r\n"))
            put("attackType", JsonPrimitive("sniper"))
            putJsonArray("payloads") { add("a"); add("b"); add("c") }
            put("host", JsonPrimitive("t.com"))
        }
        val r = Results.json.decodeFromJsonElement(IntruderResult.serializer(), res.structuredContent!!)
        assertEquals(3, r.sent)
        assertTrue(r.anomaly) // first response is 302, others 200
        assertTrue(r.distinctOutcomes.size >= 2)
        assertTrue(r.sample.isNotEmpty())
    }

    @Test
    fun `intruder_attack clusterbomb uses payloadSets`() {
        val res = call("intruder_attack") {
            put("template", JsonPrimitive("GET /u/§1§/§2§ HTTP/1.1\r\nHost: t\r\n\r\n"))
            put("attackType", JsonPrimitive("clusterbomb"))
            putJsonArray("payloadSets") {
                add(buildJsonArray { add("a"); add("b") })
                add(buildJsonArray { add("1"); add("2") })
            }
            put("host", JsonPrimitive("t.com"))
        }
        val r = Results.json.decodeFromJsonElement(IntruderResult.serializer(), res.structuredContent!!)
        assertEquals(4, r.sent)
    }

    @Test
    fun `intruder_attack errors on missing payloads`() {
        val res = call("intruder_attack") {
            put("template", JsonPrimitive("GET /u/§1§ HTTP/1.1\r\nHost: t\r\n\r\n"))
            put("host", JsonPrimitive("t.com"))
        }
        assertTrue(res.isError == true)
    }

    @Test
    fun `organizer, ws, bcheck, options, persistence`() {
        call("organizer_send") { put("content", JsonPrimitive("GET / HTTP/1.1\r\nHost: t\r\n\r\n")); put("host", JsonPrimitive("t.com")) }
        assertTrue(actions.organizerSent)

        val ws = Results.json.decodeFromJsonElement(WsSendResult.serializer(),
            call("ws_send") { put("host", JsonPrimitive("t.com")); put("message", JsonPrimitive("ping")); put("waitMs", JsonPrimitive(0)) }.structuredContent!!)
        assertTrue(ws.connected); assertEquals(listOf("echo:ping"), ws.messages)

        val bc = Results.json.decodeFromJsonElement(ImportOutcome.serializer(),
            call("bcheck_import") { put("script", JsonPrimitive("rule x")) }.structuredContent!!)
        assertEquals("LOADED", bc.status)

        call("persistence_set") { put("key", JsonPrimitive("k")); put("value", JsonPrimitive("v")) }
        val got = Results.json.decodeFromJsonElement(PersistedValue.serializer(),
            call("persistence_get") { put("key", JsonPrimitive("k")) }.structuredContent!!)
        assertEquals("v", got.value)

        val te = Results.json.decodeFromJsonElement(TaskEngineResult.serializer(),
            call("task_engine_state") { put("state", JsonPrimitive("paused")) }.structuredContent!!)
        assertEquals("PAUSED", te.state)
    }

    @Test
    fun `phase 10 mutating + pro flags`() {
        val s = specs()
        assertTrue(s.getValue("http_send_analyze").mutating)
        assertTrue(s.getValue("intruder_attack").mutating)
        assertTrue(s.getValue("bcheck_import").proOnly)
        assertFalse(s.getValue("organizer_items").mutating)
    }
}
