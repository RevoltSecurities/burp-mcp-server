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
 * by (status, length, body-hash); a minority group is the likely race win. Never dumps N full bodies.
 */
object RaceAnalyzer {

    fun analyze(responses: List<SentExchange>): List<OutcomeGroup> {
        val groups = LinkedHashMap<String, MutableList<Int>>()
        val meta = HashMap<String, Triple<Int?, Int, String>>()
        responses.forEachIndexed { index, r ->
            val body = r.responseBytes ?: ByteArray(0)
            val hash = sha1(body)
            val key = "${r.statusCode}|${body.size}|$hash"
            groups.getOrPut(key) { mutableListOf() }.add(index)
            meta.putIfAbsent(key, Triple(r.statusCode, body.size, hash))
        }
        return groups.map { (key, indices) ->
            val (status, len, hash) = meta.getValue(key)
            OutcomeGroup(status = status, responseLength = len, bodyHash = hash.take(12), count = indices.size, exampleIndex = indices.first())
        }
    }

    /** True if responses diverged (more than one distinct outcome) — a possible race condition. */
    fun isAnomalous(groups: List<OutcomeGroup>): Boolean = groups.size > 1

    private fun sha1(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-1").digest(bytes).joinToString("") { "%02x".format(it) }
}
