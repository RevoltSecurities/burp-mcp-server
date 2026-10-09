package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RaceAnalyzerTest {

    private fun ex(status: Int, body: String) = SentExchange(status, "text/html", "req".toByteArray(), body.toByteArray())

    @Test
    fun `identical responses collapse to one group`() {
        val groups = RaceAnalyzer.analyze(List(10) { ex(200, "same") })
        assertEquals(1, groups.size)
        assertEquals(10, groups.first().count)
        assertFalse(RaceAnalyzer.isAnomalous(groups))
    }

    @Test
    fun `a divergent response is flagged as anomalous`() {
        val responses = List(9) { ex(429, "rate limited") } + ex(200, "success!")
        val groups = RaceAnalyzer.analyze(responses)
        assertEquals(2, groups.size)
        assertTrue(RaceAnalyzer.isAnomalous(groups))
        assertTrue(groups.any { it.count == 1 && it.status == 200 }) // the race win
    }
}

class RaceToolsTest {

    private class RecordingActions : BurpActions {
        var lastCount = 0
        var lastMode = ""
        override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String) =
            SentExchange(200, null, raw.toByteArray(), "ok".toByteArray())
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
        override fun sendParallel(requests: List<RawTarget>, mode: String): List<SentExchange> {
            lastCount = requests.size; lastMode = mode
            // simulate a race win: one different response
            return requests.mapIndexed { i, r -> SentExchange(if (i == 0) 200 else 429, null, r.raw.toByteArray(), (if (i == 0) "WIN" else "nope").toByteArray()) }
        }
        override fun managedEngineAvailable() = false
    }

    private val registry = MessageRegistry()

    private fun tools(scopeOnly: Boolean, inScope: Boolean, actions: BurpActions) =
        RaceTools(actions, registry, { scopeOnly }, { inScope }).build().associateBy { it.id }

    private fun call(spec: ToolSpec, build: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit) = runBlocking {
        spec.handler(Args(buildJsonObject(build)))
    }

    @Test
    fun `race tools are mutating`() {
        val t = tools(false, true, RecordingActions())
        assertTrue(t.getValue("race_parallel_send").mutating)
        assertTrue(t.getValue("race_batch_send").mutating)
    }

    @Test
    fun `parallel send fires count copies in single-packet http2 and flags the race win`() {
        val actions = RecordingActions()
        val res = call(tools(false, true, actions).getValue("race_parallel_send")) {
            put("raw_request", JsonPrimitive("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
            put("host", JsonPrimitive("x.com"))
            put("count", JsonPrimitive(20))
            put("mode", JsonPrimitive("single_packet"))
        }
        assertEquals(20, actions.lastCount)
        assertEquals("http2", actions.lastMode)
        val r = Results.json.decodeFromJsonElement(RaceResult.serializer(), res.structuredContent!!)
        assertEquals(20, r.sent)
        assertTrue(r.anomaly)
        assertEquals(2, r.distinctOutcomes.size)
        // representative handles registered
        assertTrue(r.distinctOutcomes.all { it.representativeId != null })
        assertNotNull(registry.get(r.distinctOutcomes.first().representativeId!!))
    }

    @Test
    fun `batch send requires at least two requests`() {
        val res = call(tools(false, true, RecordingActions()).getValue("race_batch_send")) {
            put("host", JsonPrimitive("x.com"))
            put("raw_requests", buildJsonArray { add("GET / HTTP/1.1\r\n\r\n") })
        }
        assertTrue(res.isError == true)
    }

    @Test
    fun `parallel send blocked out of scope`() {
        val actions = RecordingActions()
        val res = call(tools(true, false, actions).getValue("race_parallel_send")) {
            put("raw_request", JsonPrimitive("GET / HTTP/1.1\r\n\r\n"))
            put("host", JsonPrimitive("evil.com"))
        }
        assertTrue(res.isError == true)
        assertEquals(0, actions.lastCount)
    }
}
