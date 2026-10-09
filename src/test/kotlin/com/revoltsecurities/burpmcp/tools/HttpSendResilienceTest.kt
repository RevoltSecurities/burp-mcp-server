package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** A SentExchange that failed at the transport: Burp's synthetic status-0 empty response (error==null). */
private fun degenerate() = SentExchange(statusCode = 0, mimeType = null, requestBytes = ByteArray(0), responseBytes = ByteArray(0), error = null)
private fun ok200(server: String? = null): SentExchange {
    val head = buildString {
        append("HTTP/1.1 200 OK\r\n")
        if (server != null) append("Server: $server\r\n")
        append("Content-Type: text/html\r\n\r\nbody")
    }
    return SentExchange(200, "text/html", "GET / HTTP/1.1\r\n\r\n".toByteArray(), head.toByteArray())
}

/** BurpActions fake whose send result depends on the HTTP mode, to drive the fallback logic. */
private class ModeFake(val perMode: (String) -> SentExchange) : BurpActions {
    override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String) = perMode(mode)
    override fun sendParallel(requests: List<RawTarget>, mode: String) = requests.map { perMode(mode) }
    override fun sendToRepeater(raw: String, host: String, port: Int, secure: Boolean, name: String?) {}
    override fun sendToIntruder(raw: String, host: String, port: Int, secure: Boolean, name: String?) {}
    override fun includeInScope(url: String) {}
    override fun excludeFromScope(url: String) {}
    override fun setIntercept(enabled: Boolean) {}
    override fun isInterceptEnabled() = false
    override fun cookies(): List<CookieDTO> = emptyList()
    override fun setCookie(name: String, value: String, domain: String, path: String?, expiresEpochSec: Long?) {}
    override fun createIssue(issue: NewIssue) = true
    override fun addToSiteMap(raw: String, host: String, port: Int, secure: Boolean, responseRaw: String?) {}
    override fun managedEngineAvailable() = false
}

class HttpSendHelperTest {

    @Test
    fun `status 0 and null status are degenerate, a real status is not`() {
        assertTrue(HttpSend.isDegenerate(degenerate()))
        assertTrue(HttpSend.isDegenerate(SentExchange(null, null, ByteArray(0), null, "boom")))
        assertFalse(HttpSend.isDegenerate(ok200()))
    }

    @Test
    fun `select probes fallback modes and returns the one that works for auto`() {
        // auto and http2 fail, http1 works — mirrors the live AWS target.
        val sel = HttpSend.select("auto") { m -> if (m == "http1") ok200() else degenerate() }
        assertTrue(sel.worked)
        assertEquals("http1", sel.mode)
        assertTrue(sel.switchedFrom("auto"))
        assertEquals(listOf("auto", "http1"), sel.tried)
    }

    @Test
    fun `select honours an explicit mode without probing`() {
        var calls = 0
        val sel = HttpSend.select("http2") { calls++; degenerate() }
        assertEquals(1, calls)
        assertEquals("http2", sel.mode)
        assertFalse(sel.worked)
    }

    @Test
    fun `edge signature is extracted only for known WAF or CDN servers`() {
        assertEquals("awselb/2.0", HttpSend.edgeSignature(ok200("awselb/2.0")))
        assertEquals("cloudflare", HttpSend.edgeSignature(ok200("cloudflare")))
        assertNull(HttpSend.edgeSignature(ok200("nginx")))
        assertNull(HttpSend.edgeSignature(ok200(null)))
    }

    @Test
    fun `allDegenerate and degenerateCount`() {
        assertTrue(HttpSend.allDegenerate(listOf(degenerate(), degenerate())))
        assertFalse(HttpSend.allDegenerate(listOf(degenerate(), ok200())))
        assertEquals(1, HttpSend.degenerateCount(listOf(degenerate(), ok200())))
    }
}

class HttpSendToolTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun httpSendTool(actions: BurpActions): ToolSpec =
        ActionTools(actions, MessageRegistry(), scopeOnly = { false }, isInScope = { true }, unsafeEnabled = { true })
            .build().first { it.id == "http_send" }

    private fun call(tool: ToolSpec, args: Map<String, String>): SendResult {
        val result = runBlocking {
            tool.handler(Args(buildJsonObject { args.forEach { (k, v) -> put(k, JsonPrimitive(v)) } }))
        }
        val text = (result.content.first() as TextContent).text!!
        return json.decodeFromString(SendResult.serializer(), text)
    }

    @Test
    fun `http_send auto falls back to http1 when http2 degenerates`() {
        val tool = httpSendTool(ModeFake { m -> if (m == "http1") ok200() else degenerate() })
        val r = call(tool, mapOf("host" to "t", "path" to "/"))
        assertTrue(r.ok, "a working http1 fallback must report ok")
        assertEquals(200, r.status)
        assertEquals("http1", r.httpModeUsed)
    }

    @Test
    fun `http_send reports a transport failure when every mode degenerates`() {
        val tool = httpSendTool(ModeFake { degenerate() })
        val r = call(tool, mapOf("host" to "t", "path" to "/"))
        assertFalse(r.ok, "an all-modes-failed send must NOT be reported ok")
        assertEquals("no response", r.statusText)
        assertTrue(r.error != null && r.note.contains("httpMode=http1") || r.note.contains("http1"))
    }
}
