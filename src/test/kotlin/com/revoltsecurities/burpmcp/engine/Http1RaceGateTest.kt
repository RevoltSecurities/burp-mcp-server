package com.revoltsecurities.burpmcp.engine

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Tests the clean-room last-byte gate against a local HTTP/1 server. The server does not respond until it has
 * read the full request terminator (CRLFCRLF) — so a passing test proves the gate actually delivers the
 * held-back final byte after the synchronized release.
 */
class Http1RaceGateTest {

    private var server: ServerSocket? = null
    private val running = AtomicBoolean(true)
    val fullyReadAt = ConcurrentLinkedQueue<Long>()

    private fun startServer(responder: (requestText: String) -> String): Int {
        val ss = ServerSocket(0)
        server = ss
        thread(isDaemon = true, name = "test-http-server") {
            while (running.get()) {
                val sock = runCatching { ss.accept() }.getOrNull() ?: break
                thread(isDaemon = true) { handle(sock, responder) }
            }
        }
        return ss.localPort
    }

    private fun handle(sock: Socket, responder: (String) -> String) {
        sock.use {
            val input = it.getInputStream()
            val acc = StringBuilder()
            val b = ByteArray(1024)
            // Read until the request head terminator — proves the final (held-back) byte arrived.
            while (!acc.contains("\r\n\r\n")) {
                val r = runCatching { input.read(b) }.getOrDefault(-1)
                if (r < 0) return
                acc.append(String(b, 0, r, Charsets.ISO_8859_1))
            }
            fullyReadAt.add(System.nanoTime())
            val resp = responder(acc.toString())
            it.getOutputStream().apply { write(resp.toByteArray(Charsets.ISO_8859_1)); flush() }
        }
    }

    @AfterEach
    fun tearDown() {
        running.set(false)
        runCatching { server?.close() }
    }

    private fun ok(len: Int = 2) = "HTTP/1.1 200 OK\r\nContent-Length: $len\r\n\r\n" + "o".repeat(len)

    @Test
    fun `fires N synchronized requests and reads every response`() {
        val port = startServer { ok() }
        val reqs = (0 until 5).map {
            Http1RaceGate.Req("GET /race HTTP/1.1\r\nHost: localhost\r\n\r\n", "127.0.0.1", port, secure = false)
        }
        val out = Http1RaceGate.fire(reqs, connectTimeoutMs = 3000, readTimeoutMs = 3000)
        assertEquals(5, out.size)
        out.forEach { r ->
            assertNull(r.error, "no connection should error")
            assertEquals(200, r.status)
            assertNotNull(r.responseBytes)
            assertTrue(String(r.responseBytes!!, Charsets.ISO_8859_1).contains("oo"))
        }
        // All five requests were fully read by the server (the held-back byte was delivered to each).
        assertEquals(5, fullyReadAt.size)
    }

    @Test
    fun `the final bytes are released in a tight window after priming`() {
        val port = startServer { ok() }
        val reqs = (0 until 8).map {
            Http1RaceGate.Req("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "127.0.0.1", port, secure = false)
        }
        Http1RaceGate.fire(reqs, connectTimeoutMs = 3000, readTimeoutMs = 3000)
        val times = fullyReadAt.sorted()
        assertEquals(8, times.size)
        // The spread between the first and last full-read should be small (released together), not serialized.
        // Generous bound to stay non-flaky on CI: 250ms. Serialized sends would be far larger under load.
        val spreadMs = (times.last() - times.first()) / 1_000_000.0
        assertTrue(spreadMs < 250, "release spread was ${spreadMs}ms — expected a tight synchronized window")
    }

    @Test
    fun `a failing connection does not deadlock or stall the others`() {
        val port = startServer { ok() }
        // One request points at a closed port; the rest are valid.
        val reqs = listOf(
            Http1RaceGate.Req("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "127.0.0.1", port, secure = false),
            Http1RaceGate.Req("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "127.0.0.1", 1, secure = false), // port 1: refused
            Http1RaceGate.Req("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "127.0.0.1", port, secure = false),
        )
        val out = Http1RaceGate.fire(reqs, connectTimeoutMs = 2000, readTimeoutMs = 2000)
        assertEquals(3, out.size)
        assertEquals(200, out[0].status)
        assertNotNull(out[1].error) // the refused connection reports an error, doesn't hang the gate
        assertEquals(200, out[2].status)
    }
}
