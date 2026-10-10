package com.revoltsecurities.burpmcp.tools

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HttpSendAutoRetrySafetyTest {

    private fun degenerate() = SentExchange(null, null, ByteArray(0), null, "no response")
    private fun ok(code: Int) = SentExchange(code, "text/html", ByteArray(0), "HTTP/1.1 $code OK\r\n\r\n".toByteArray())

    @Test
    fun `only safe methods are auto-retryable`() {
        assertTrue(HttpSend.autoRetryOk("GET"))
        assertTrue(HttpSend.autoRetryOk("head"))
        assertTrue(HttpSend.autoRetryOk("OPTIONS"))
        assertFalse(HttpSend.autoRetryOk("POST"))
        assertFalse(HttpSend.autoRetryOk("PUT"))
        assertFalse(HttpSend.autoRetryOk("DELETE"))
        assertFalse(HttpSend.autoRetryOk(null))
    }

    @Test
    fun `auto with autoRetry disabled sends exactly once even on a degenerate response`() {
        var sends = 0
        val sel = HttpSend.select("auto", autoRetry = false) { sends++; degenerate() }
        assertEquals(1, sends) // a mutating request is NEVER re-sent across transports
        assertEquals(listOf("auto"), sel.tried)
        assertFalse(sel.worked)
    }

    @Test
    fun `auto with autoRetry enabled probes fallback modes until one works`() {
        var sends = 0
        val sel = HttpSend.select("auto", autoRetry = true) { m -> sends++; if (m == "http1") ok(200) else degenerate() }
        assertTrue(sel.worked)
        assertEquals("http1", sel.mode)
        assertTrue(sends in 2..3) // tried auto then http1
    }

    @Test
    fun `an explicit mode never re-sends regardless of autoRetry`() {
        var sends = 0
        val sel = HttpSend.select("http2", autoRetry = true) { sends++; degenerate() }
        assertEquals(1, sends)
        assertEquals(listOf("http2"), sel.tried)
    }
}
