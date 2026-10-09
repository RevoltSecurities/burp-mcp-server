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
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RequestBuilderTest {

    @Test
    fun `builds a well-formed request with Host and Content-Length`() {
        val raw = RequestBuilder.build("POST", "/x", "api.example.com", 443, true, "HTTP/1.1", emptyList(), "{\"a\":1}", "json")
        assertTrue(raw.startsWith("POST /x HTTP/1.1\r\n"))
        assertTrue(raw.contains("Host: api.example.com\r\n"))
        assertTrue(raw.contains("Content-Type: application/json\r\n"))
        assertTrue(raw.contains("Content-Length: 7\r\n")) // {"a":1} = 7 bytes
        assertTrue(raw.endsWith("\r\n\r\n{\"a\":1}"))
    }

    @Test
    fun `non-default port is included in the Host header`() {
        val raw = RequestBuilder.build("GET", "/", "h", 8443, true, "HTTP/1.1", emptyList(), null, null)
        assertTrue(raw.contains("Host: h:8443\r\n"))
    }

    @Test
    fun `path is normalized to start with a slash`() {
        val raw = RequestBuilder.build("GET", "health", "h", 443, true, "HTTP/1.1", emptyList(), null, null)
        assertTrue(raw.startsWith("GET /health HTTP/1.1\r\n"))
    }

    @Test
    fun `graphql wraps a bare query and sets json content type`() {
        val raw = RequestBuilder.build("POST", "/graphql", "h", 443, true, "HTTP/1.1", emptyList(), "query { me }", "graphql")
        assertTrue(raw.contains("Content-Type: application/json\r\n"))
        assertTrue(raw.endsWith("{\"query\":\"query { me }\"}"))
    }

    @Test
    fun `graphql passes a full json object through unchanged`() {
        val body = "{\"query\":\"q\",\"variables\":{}}"
        val raw = RequestBuilder.build("POST", "/graphql", "h", 443, true, "HTTP/1.1", emptyList(), body, "graphql")
        assertTrue(raw.endsWith(body))
    }

    @Test
    fun `invalid json body is rejected with an actionable message`() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            RequestBuilder.build("POST", "/", "h", 443, true, "HTTP/1.1", emptyList(), "{not json", "json")
        }
        assertTrue(e.message!!.contains("not valid JSON"))
    }

    @Test
    fun `soapxml and xml and form set the right content types`() {
        assertTrue(RequestBuilder.build("POST", "/", "h", 443, true, "HTTP/1.1", emptyList(), "<x/>", "soapxml").contains("Content-Type: application/soap+xml"))
        assertTrue(RequestBuilder.build("POST", "/", "h", 443, true, "HTTP/1.1", emptyList(), "<x/>", "xml").contains("Content-Type: application/xml\r\n"))
        assertTrue(RequestBuilder.build("POST", "/", "h", 443, true, "HTTP/1.1", emptyList(), "a=1&b=2", "form").contains("Content-Type: application/x-www-form-urlencoded\r\n"))
    }

    @Test
    fun `a caller-supplied wrong Content-Length is overridden to the real size`() {
        val raw = RequestBuilder.build("POST", "/", "h", 443, true, "HTTP/1.1", listOf("Content-Length: 999"), "ab", "raw")
        assertTrue(raw.contains("Content-Length: 2\r\n"))
        assertFalse(raw.contains("Content-Length: 999"))
    }

    @Test
    fun `an explicit content-type header overrides the bodyType default`() {
        val raw = RequestBuilder.build("POST", "/", "h", 443, true, "HTTP/1.1", listOf("Content-Type: text/plain"), "{}", "json")
        assertTrue(raw.contains("Content-Type: text/plain\r\n"))
        assertFalse(raw.contains("Content-Type: application/json"))
    }

    @Test
    fun `fromArgs derives host port secure and path from a url`() {
        val b = RequestBuilder.fromArgs(Args(buildJsonObject {
            put("method", JsonPrimitive("GET")); put("url", JsonPrimitive("https://api.example.com/v1/users?q=1"))
        }))
        assertEquals("api.example.com", b.host)
        assertEquals(443, b.port)
        assertTrue(b.secure)
        assertTrue(b.raw.startsWith("GET /v1/users?q=1 HTTP/1.1\r\n"))
        assertTrue(b.raw.contains("Host: api.example.com\r\n"))
    }

    @Test
    fun `fromArgs needs host or url`() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            RequestBuilder.fromArgs(Args(buildJsonObject { put("method", JsonPrimitive("GET")) }))
        }
        assertTrue(e.message!!.contains("host") || e.message!!.contains("url"))
    }

    @Test
    fun `fromArgsSide reads suffixed fields with fallback to shared`() {
        val args = Args(buildJsonObject {
            put("host", JsonPrimitive("api.example.com"))  // shared
            put("pathA", JsonPrimitive("/users/1"))
            put("pathB", JsonPrimitive("/users/2"))
            put("method", JsonPrimitive("GET"))            // shared, used by both sides
        })
        val a = RequestBuilder.fromArgsSide(args, "A")
        val b = RequestBuilder.fromArgsSide(args, "B")
        assertEquals("api.example.com", a.host)
        assertTrue(a.raw.startsWith("GET /users/1 HTTP/1.1\r\n"))
        assertTrue(b.raw.startsWith("GET /users/2 HTTP/1.1\r\n"))
    }
}

class StructuredHttpSendTest {

    private val json = Json { ignoreUnknownKeys = true }

    private class CapturingFake : BurpActions {
        var lastRaw: String? = null
        override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String): SentExchange {
            lastRaw = raw
            val resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok".toByteArray()
            return SentExchange(200, "text/html", raw.toByteArray(), resp)
        }
        override fun sendParallel(requests: List<RawTarget>, mode: String) = requests.map { sendRequest(it.raw, it.host, it.port, it.secure, mode) }
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

    @Test
    fun `http_send builds a correct request from structured fields with no raw content`() {
        val fake = CapturingFake()
        val tool = ActionTools(fake, MessageRegistry(), scopeOnly = { false }, isInScope = { true }, unsafeEnabled = { true })
            .build().first { it.id == "http_send" }
        val res = runBlocking {
            tool.handler(Args(buildJsonObject {
                put("method", JsonPrimitive("POST"))
                put("host", JsonPrimitive("api.example.com"))
                put("path", JsonPrimitive("/v1/login"))
                put("body", JsonPrimitive("{\"u\":\"a\"}"))
                put("bodyType", JsonPrimitive("json"))
            }))
        }
        val r = json.decodeFromString(SendResult.serializer(), (res.content.first() as TextContent).text!!)
        assertTrue(r.ok)
        assertEquals("api.example.com", r.targetHost)
        // The server assembled a byte-correct request: method, Host, Content-Type and a correct Content-Length.
        val sent = fake.lastRaw!!
        assertTrue(sent.startsWith("POST /v1/login HTTP/1.1\r\n"))
        assertTrue(sent.contains("Host: api.example.com\r\n"))
        assertTrue(sent.contains("Content-Type: application/json\r\n"))
        assertTrue(sent.contains("Content-Length: 9\r\n")) // {"u":"a"} = 9 bytes
    }
}
