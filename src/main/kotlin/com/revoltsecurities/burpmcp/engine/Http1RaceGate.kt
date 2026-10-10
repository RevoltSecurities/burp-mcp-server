package com.revoltsecurities.burpmcp.engine

import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

/**
 * Clean-room HTTP/1.1 **last-byte synchronization** gate for race-condition testing.
 *
 * Implements the public last-byte-sync technique (PortSwigger / James Kettle research, "Smashing the state
 * machine"): open one raw connection per request, write every byte of each request EXCEPT the final byte and
 * flush, wait at a barrier until every connection is primed, then release the held-back final byte on all
 * connections simultaneously with `TCP_NODELAY`. The server therefore receives N complete requests within a
 * few microseconds of one another — the tightest HTTP/1 race window achievable without kernel support.
 *
 * This is a from-scratch implementation on plain JDK networking (`java.net.Socket` / `javax.net.ssl`). It
 * contains no third-party code and no Burp dependency, so it is unit-testable against a local server and runs
 * identically with or without Burp loaded. TLS verification is intentionally disabled (this is an offensive
 * testing tool pointed at operator-chosen targets), and ALPN is pinned to `http/1.1` so the connection never
 * upgrades to HTTP/2.
 */
object Http1RaceGate {

    data class Req(val raw: String, val host: String, val port: Int, val secure: Boolean)

    /** One request's outcome. [status] is null when no response line was read; [elapsedNanos] is measured from
     *  the synchronized release of the final byte to the first response byte. */
    data class Resp(
        val index: Int,
        val status: Int?,
        val responseBytes: ByteArray?,
        val error: String?,
        val elapsedNanos: Long,
    )

    /**
     * Fire all [requests] with last-byte synchronization. Returns one [Resp] per request, in input order.
     * Never throws: a per-connection failure is reported in that request's [Resp.error] and does not stall the
     * others (a failed connection still releases the barrier so the gate can never deadlock).
     */
    fun fire(
        requests: List<Req>,
        connectTimeoutMs: Int = 10_000,
        readTimeoutMs: Int = 15_000,
    ): List<Resp> {
        val n = requests.size
        if (n == 0) return emptyList()

        val primed = CountDownLatch(n) // counts down once each connection has written its all-but-last-byte prefix
        val release = CountDownLatch(1) // opened once, releases every held-back final byte together
        val results = arrayOfNulls<Resp>(n)

        val workers = requests.mapIndexed { i, req ->
            thread(start = true, name = "race-gate-$i", isDaemon = true) {
                var socket: Socket? = null
                try {
                    socket = openSocket(req, connectTimeoutMs, readTimeoutMs)
                    val out = socket.getOutputStream()
                    val bytes = req.raw.toByteArray(Charsets.ISO_8859_1)
                    val hold = if (bytes.size >= 1) 1 else 0
                    if (bytes.size > hold) {
                        out.write(bytes, 0, bytes.size - hold)
                        out.flush()
                    }
                    primed.countDown()
                    release.await() // park until every connection is primed and the main thread opens the gate
                    val start = System.nanoTime()
                    if (hold > 0) {
                        out.write(bytes, bytes.size - hold, hold) // the single synchronized byte
                        out.flush()
                    }
                    val resp = readResponse(socket.getInputStream())
                    results[i] = Resp(i, parseStatus(resp), resp, null, System.nanoTime() - start)
                } catch (e: Exception) {
                    primed.countDown() // never let a failure deadlock the barrier
                    results[i] = Resp(i, null, null, e.message ?: e.javaClass.simpleName, 0)
                } finally {
                    runCatching { socket?.close() }
                }
            }
        }

        // Wait until every connection has buffered its prefix (or we hit the connect budget), then release all.
        primed.await(connectTimeoutMs.toLong() + 5_000, TimeUnit.MILLISECONDS)
        release.countDown()
        val joinBudget = readTimeoutMs.toLong() + 5_000
        workers.forEach { it.join(joinBudget) }
        return (0 until n).map { results[it] ?: Resp(it, null, null, "no result (timed out)", 0) }
    }

    private fun openSocket(req: Req, connectTimeoutMs: Int, readTimeoutMs: Int): Socket {
        val raw = Socket()
        raw.tcpNoDelay = true // critical: do not let Nagle coalesce/delay the final byte
        raw.connect(InetSocketAddress(req.host, req.port), connectTimeoutMs)
        raw.soTimeout = readTimeoutMs
        if (!req.secure) return raw
        val ssl = trustAllFactory().createSocket(raw, req.host, req.port, true) as SSLSocket
        val params = ssl.sslParameters
        params.applicationProtocols = arrayOf("http/1.1") // pin ALPN so we never negotiate HTTP/2
        ssl.sslParameters = params
        ssl.tcpNoDelay = true
        ssl.startHandshake()
        return ssl
    }

    /** Read a full HTTP/1 response: status line + headers, then body by Content-Length, chunked, or EOF. */
    private fun readResponse(input: InputStream): ByteArray {
        val buf = java.io.ByteArrayOutputStream(8_192)
        // 1. Read head (up to CRLFCRLF).
        var headerEnd = -1
        val tmp = ByteArray(4_096)
        while (headerEnd < 0) {
            val r = input.read(tmp)
            if (r < 0) return buf.toByteArray()
            buf.write(tmp, 0, r)
            headerEnd = indexOfCrlfCrlf(buf.toByteArray())
        }
        val all = buf.toByteArray()
        val head = String(all, 0, headerEnd, Charsets.ISO_8859_1)
        val bodyAlready = all.size - (headerEnd + 4)
        val contentLength = Regex("(?im)^content-length:\\s*(\\d+)\\s*$").find(head)?.groupValues?.get(1)?.toIntOrNull()
        val chunked = Regex("(?im)^transfer-encoding:\\s*.*chunked").containsMatchIn(head)

        when {
            contentLength != null -> {
                var remaining = contentLength - bodyAlready
                while (remaining > 0) {
                    val r = input.read(tmp, 0, minOf(tmp.size, remaining))
                    if (r < 0) break
                    buf.write(tmp, 0, r); remaining -= r
                }
            }
            chunked -> {
                // Read until the terminating 0-length chunk, bounded by the socket read timeout.
                while (true) {
                    val r = input.read(tmp)
                    if (r < 0) break
                    buf.write(tmp, 0, r)
                    val s = buf.toByteArray()
                    if (endsWithChunkTerminator(s)) break
                }
            }
            else -> {
                // No length signal: read until the server closes (bounded by soTimeout).
                while (true) {
                    val r = runCatching { input.read(tmp) }.getOrDefault(-1)
                    if (r < 0) break
                    buf.write(tmp, 0, r)
                }
            }
        }
        return buf.toByteArray()
    }

    private fun parseStatus(response: ByteArray): Int? {
        val line = String(response, 0, minOf(response.size, 64), Charsets.ISO_8859_1).substringBefore('\r').substringBefore('\n')
        return line.split(' ').getOrNull(1)?.toIntOrNull()
    }

    private fun indexOfCrlfCrlf(b: ByteArray): Int {
        for (i in 0..b.size - 4) {
            if (b[i] == '\r'.code.toByte() && b[i + 1] == '\n'.code.toByte() && b[i + 2] == '\r'.code.toByte() && b[i + 3] == '\n'.code.toByte()) return i
        }
        return -1
    }

    private fun endsWithChunkTerminator(b: ByteArray): Boolean {
        // The body ends with the final 0-length chunk + a blank line: "0\r\n\r\n" with no trailers, or
        // "0\r\n<Trailer: v>\r\n...\r\n\r\n" with them. Require a "\r\n0\r\n" final-chunk marker AND a
        // closing CRLFCRLF, so trailer-emitting servers don't make us block until the read timeout.
        if (b.size < 5) return false
        val tail = String(b, maxOf(0, b.size - 512), minOf(512, b.size), Charsets.ISO_8859_1)
        if (!tail.endsWith("\r\n\r\n")) return false
        return tail.endsWith("0\r\n\r\n") || tail.contains("\r\n0\r\n")
    }

    @Volatile
    private var cachedFactory: SSLSocketFactory? = null

    private fun trustAllFactory(): SSLSocketFactory {
        cachedFactory?.let { return it }
        val ctx = SSLContext.getInstance("TLS")
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        ctx.init(null, arrayOf(trustAll), SecureRandom())
        return ctx.socketFactory.also { cachedFactory = it }
    }
}
