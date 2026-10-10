package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable
import java.security.MessageDigest

@Serializable
data class OutcomeGroup(
    val status: Int?,
    val responseLength: Int,
    val bodyHash: String,
    val count: Int,
    val exampleIndex: Int,
    val representativeId: String? = null,
)

/**
 * Pure grouping of race/batch responses so a 30-request run collapses to a few lines: responses are grouped
 * by (status, normalized-body-hash); a minority group is the likely race win. Never dumps N full bodies.
 *
 * **Why body-only + normalization:** grouping on the *whole* response made every response its own group on any
 * target whose responses carry a per-request value — `Date`, `X-Request-Id`, `X-Runtime`, `Set-Cookie` nonces,
 * etc. — producing a false "outcomes DIVERGED / likely race win" on every run. Those volatile values live in
 * the response **headers**, so we hash the **body** only (status is already a separate key). In the body we
 * additionally mask the two unambiguously-volatile token shapes — **UUIDs** and **ISO-8601 timestamps** — so
 * responses that differ only by an embedded nonce still collapse. We deliberately do NOT mask numbers, amounts
 * or arbitrary hex: those can be the real race signal (a balance, a count), and a false negative that hides a
 * genuine race win is far worse than a tidier grouping.
 */
object RaceAnalyzer {

    fun analyze(responses: List<SentExchange>): List<OutcomeGroup> {
        val groups = LinkedHashMap<String, MutableList<Int>>()
        val meta = HashMap<String, Triple<Int?, Int, String>>()
        responses.forEachIndexed { index, r ->
            val full = r.responseBytes ?: ByteArray(0)
            val body = extractBody(full)
            val hash = sha1(normalizeVolatile(body))
            val key = "${r.statusCode}|$hash"
            groups.getOrPut(key) { mutableListOf() }.add(index)
            meta.putIfAbsent(key, Triple(r.statusCode, full.size, hash))
        }
        return groups.map { (key, indices) ->
            val (status, len, hash) = meta.getValue(key)
            OutcomeGroup(status = status, responseLength = len, bodyHash = hash.take(12), count = indices.size, exampleIndex = indices.first())
        }
    }

    /** True if responses diverged (more than one distinct outcome) — a possible race condition. */
    fun isAnomalous(groups: List<OutcomeGroup>): Boolean = groups.size > 1

    /** Body after the first CRLFCRLF; the whole buffer when there is no header/body separator (e.g. a test
     *  double that supplies a bare body, or a malformed response). */
    private fun extractBody(full: ByteArray): ByteArray {
        val sep = indexOfCrlfCrlf(full)
        return if (sep >= 0) full.copyOfRange(sep + 4, full.size) else full
    }

    /** Mask only high-confidence per-request volatile tokens so a lone nonce doesn't split an otherwise
     *  identical response. Conservative on purpose (see class doc): UUIDs and ISO-8601 timestamps only. */
    private fun normalizeVolatile(body: ByteArray): ByteArray {
        if (body.isEmpty()) return body
        var s = String(body, Charsets.ISO_8859_1)
        s = UUID_RE.replace(s, "<uuid>")
        s = ISO_TS_RE.replace(s, "<ts>")
        return s.toByteArray(Charsets.ISO_8859_1)
    }

    private val UUID_RE = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
    private val ISO_TS_RE = Regex("\\d{4}-\\d{2}-\\d{2}[Tt ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:[Zz]|[+-]\\d{2}:?\\d{2})?")

    private fun indexOfCrlfCrlf(b: ByteArray): Int {
        for (i in 0..b.size - 4) {
            if (b[i] == CR && b[i + 1] == LF && b[i + 2] == CR && b[i + 3] == LF) return i
        }
        return -1
    }

    private const val CR = '\r'.code.toByte()
    private const val LF = '\n'.code.toByte()

    private fun sha1(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-1").digest(bytes).joinToString("") { "%02x".format(it) }
}
