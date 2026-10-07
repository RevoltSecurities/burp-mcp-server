package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HttpParseTest {

    private val req = "POST /login?next=/home HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=alice&pw=secret"

    @Test
    fun `parse request line and headers`() {
        val p = HttpParse.parseRequest(req, includeBody = true)
        assertEquals("POST", p.method)
        assertEquals("/login?next=/home", p.target)
        assertEquals("x.com", p.headers.first { it.name == "Host" }.value)
        assertTrue(p.body!!.contains("user=alice"))
    }

    @Test
    fun `extract query and form params`() {
        val params = HttpParse.extractParams(req)
        assertTrue(params.any { it.name == "next" && it.source == "query" })
        assertTrue(params.any { it.name == "user" && it.value == "alice" && it.source == "body" })
    }

    @Test
    fun `find reflected values in response`() {
        val resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>welcome alice</p>"
        val reflected = HttpParse.findReflected(req, resp)
        assertTrue(reflected.any { it.name == "user" && it.reflections == 1 })
    }

    @Test
    fun `parse response status`() {
        val r = HttpParse.parseResponse("HTTP/1.1 404 Not Found\r\nX: y\r\n\r\nnope", includeBody = false)
        assertEquals(404, r.statusCode)
        assertEquals("Not Found", r.reason)
    }

    @Test
    fun `diff reports added and removed lines`() {
        val d = HttpParse.diff("a\nb\nc", "a\nc\nd")
        assertTrue(d.contains("- b"))
        assertTrue(d.contains("+ d"))
    }
}

private class FakeActions : BurpActions {
    var sendCalled = false
    var lastIssue: NewIssue? = null
    override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String): SentExchange {
        sendCalled = true
        return SentExchange(200, "text/html", raw.toByteArray(), "HTTP/1.1 200 OK\r\n\r\nbody".toByteArray())
    }
    override fun sendToRepeater(raw: String, host: String, port: Int, secure: Boolean, name: String?) {}
    override fun sendToIntruder(raw: String, host: String, port: Int, secure: Boolean, name: String?) {}
    override fun includeInScope(url: String) {}
    override fun excludeFromScope(url: String) {}
    override fun setIntercept(enabled: Boolean) {}
    override fun isInterceptEnabled() = false
    override fun cookies() = listOf(CookieDTO("sid", "secret", "x.com", "/"))
    override fun setCookie(name: String, value: String, domain: String, path: String?, expiresEpochSec: Long?) {}
    override fun createIssue(issue: NewIssue): Boolean { lastIssue = issue; return true }
    override fun addToSiteMap(raw: String, host: String, port: Int, secure: Boolean, responseRaw: String?) {}
    override fun sendParallel(requests: List<RawTarget>, mode: String): List<SentExchange> =
        requests.map { SentExchange(200, "text/html", it.raw.toByteArray(), "ok".toByteArray()) }
    override fun managedEngineAvailable(): Boolean = false
}

class ActionToolsTest {

    private val registry = MessageRegistry()

    private fun tools(scopeOnly: Boolean, inScope: Boolean, actions: BurpActions): Map<String, ToolSpec> =
        ActionTools(actions, registry, { scopeOnly }, { inScope }).build().associateBy { it.id }

    private fun call(spec: ToolSpec, args: Map<String, Any?>) = runBlocking {
        spec.handler(
            Args(
                buildJsonObject {
                    args.forEach { (k, v) ->
                        when (v) {
                            is String -> put(k, JsonPrimitive(v))
                            is Int -> put(k, JsonPrimitive(v))
                            is Boolean -> put(k, JsonPrimitive(v))
                            else -> {}
                        }
                    }
                },
            ),
        )
    }

    @Test
    fun `http_send is blocked out of scope when scope confinement is on`() {
        val fake = FakeActions()
        val t = tools(scopeOnly = true, inScope = false, actions = fake)
        val res = call(t.getValue("http_send"), mapOf("content" to "GET / HTTP/1.1\r\n\r\n", "host" to "evil.com"))
        assertTrue(res.isError == true)
        assertFalse(fake.sendCalled)
    }

    @Test
    fun `http_send sends and registers a response handle when allowed`() {
        val fake = FakeActions()
        val t = tools(scopeOnly = false, inScope = true, actions = fake)
        val res = call(t.getValue("http_send"), mapOf("content" to "GET / HTTP/1.1\r\n\r\n", "host" to "good.com"))
        assertTrue(fake.sendCalled)
        val sr = Results.json.decodeFromJsonElement(SendResult.serializer(), res.structuredContent!!)
        assertEquals(200, sr.status)
        assertNotNull(registry.get(sr.id))
    }

    @Test
    fun `cookie_jar_get redacts values by default`() {
        val t = tools(scopeOnly = false, inScope = true, actions = FakeActions())
        val res = call(t.getValue("cookie_jar_get"), emptyMap())
        val text = (res.content.first() as io.modelcontextprotocol.kotlin.sdk.types.TextContent).text
        assertTrue(text.contains("[REDACTED]"))
        assertFalse(text.contains("secret"))
    }

    @Test
    fun `issue_create forwards to actions`() {
        val fake = FakeActions()
        val t = tools(scopeOnly = false, inScope = true, actions = fake)
        call(t.getValue("issue_create"), mapOf("name" to "Test", "detail" to "d", "baseUrl" to "https://x.com/", "host" to "x.com", "severity" to "high"))
        assertEquals("Test", fake.lastIssue?.name)
        assertEquals("high", fake.lastIssue?.severity)
    }
}
