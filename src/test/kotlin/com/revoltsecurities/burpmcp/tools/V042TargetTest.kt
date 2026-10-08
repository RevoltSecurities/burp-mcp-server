package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HostTargetTest {

    @Test
    fun `derives host and port from the Host header`() {
        val ht = HttpParse.hostTarget("GET /a HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n")!!
        assertEquals("api.example.com", ht.host)
        assertEquals(8443, ht.port)
        assertNull(ht.secure) // unknown from a Host header alone
    }

    @Test
    fun `derives host, port and scheme from an absolute request-line`() {
        val ht = HttpParse.hostTarget("GET https://x.example.com/p HTTP/1.1\r\nHost: ignored\r\n\r\n")!!
        assertEquals("x.example.com", ht.host)
        assertEquals(true, ht.secure)
    }

    @Test
    fun `returns null when there is no host anywhere`() {
        assertNull(HttpParse.hostTarget("GET /a HTTP/1.1\r\nAccept: */*\r\n\r\n"))
    }

    @Test
    fun `parses a bracketed IPv6 Host header`() {
        val ht = HttpParse.hostTarget("GET /a HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n")!!
        assertEquals("::1", ht.host)
        assertEquals(8080, ht.port)
    }
}

class TargetArgsTest {

    private fun args(build: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit) = Args(buildJsonObject(build))

    @Test
    fun `explicit host wins over the Host header`() {
        val t = TargetArgs.resolve(args { put("host", JsonPrimitive("override.com")) }, "GET / HTTP/1.1\r\nHost: content.com\r\n\r\n")!!
        assertEquals("override.com", t.host); assertEquals(443, t.port); assertTrue(t.secure)
    }

    @Test
    fun `derives from content when host is omitted`() {
        val t = TargetArgs.resolve(args {}, "GET / HTTP/1.1\r\nHost: content.com:8080\r\n\r\n")!!
        assertEquals("content.com", t.host); assertEquals(8080, t.port)
    }

    @Test
    fun `null when neither host arg nor Host header`() {
        assertNull(TargetArgs.resolve(args {}, "GET / HTTP/1.1\r\nAccept: x\r\n\r\n"))
    }

    @Test
    fun `a derived port 80 implies plain HTTP, not TLS on 80`() {
        val t = TargetArgs.resolve(args {}, "GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n")!!
        assertEquals(80, t.port); assertEquals(false, t.secure)
    }

    @Test
    fun `explicit host override does not inherit the request's port or scheme`() {
        val t = TargetArgs.resolve(args { put("host", JsonPrimitive("override.com")) }, "GET / HTTP/1.1\r\nHost: content.com:8080\r\n\r\n")!!
        assertEquals("override.com", t.host); assertEquals(443, t.port); assertTrue(t.secure)
    }

    @Test
    fun `marker-stripped template derives a clean host`() {
        val t = TargetArgs.resolve(args {}, "GET /§1§ HTTP/1.1\r\nHost: §h§.evil.com\r\n\r\n".replace("§", ""))!!
        assertEquals("h.evil.com", t.host)
    }
}

private class HostCapturingActions : BurpActions {
    var lastHost: String? = null; var lastPort: Int? = null
    override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String): SentExchange {
        lastHost = host; lastPort = port
        return SentExchange(200, "text/html", raw.toByteArray(), "HTTP/1.1 200 OK\r\n\r\nok".toByteArray())
    }
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
    override fun sendParallel(requests: List<RawTarget>, mode: String) = emptyList<SentExchange>()
    override fun managedEngineAvailable() = false
}

class HostlessSendTest {

    @Test
    fun `http_send with no host derives it from the Host header for routing and scope`() {
        val actions = HostCapturingActions()
        val scoped = StringBuilder()
        val tool = ActionTools(actions, MessageRegistry(), scopeOnly = { true }, isInScope = { url -> scoped.append(url); url.contains("content.com") })
            .build().first { it.id == "http_send" }
        val res = runBlocking {
            tool.handler(Args(buildJsonObject { put("content", JsonPrimitive("GET /x HTTP/1.1\r\nHost: content.com:8080\r\n\r\n")) }))
        }
        assertEquals("content.com", actions.lastHost) // derived from Host header, not a 'host' arg
        assertEquals(8080, actions.lastPort)
        assertTrue(res.isError != true)
        assertTrue(scoped.contains("content.com")) // scope was checked against the derived host
    }

    @Test
    fun `http_send with neither host arg nor Host header errors clearly`() {
        val tool = ActionTools(HostCapturingActions(), MessageRegistry(), scopeOnly = { false }, isInScope = { true })
            .build().first { it.id == "http_send" }
        val res = runBlocking { tool.handler(Args(buildJsonObject { put("content", JsonPrimitive("GET /x HTTP/1.1\r\nAccept: x\r\n\r\n")) })) }
        assertTrue(res.isError == true)
    }
}
