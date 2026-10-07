package com.revoltsecurities.burpmcp.tools

/** Pure predicates shared by the list tools. */
object Filters {

    fun matchHost(host: String, filter: String?): Boolean =
        filter.isNullOrEmpty() || host.contains(filter, ignoreCase = true)

    fun matchMethod(method: String, filter: String?): Boolean =
        filter.isNullOrEmpty() || method.equals(filter, ignoreCase = true)

    fun matchMime(mime: String?, filter: String?): Boolean =
        filter.isNullOrEmpty() || (mime?.contains(filter, ignoreCase = true) == true)

    /** status filter: exact ("404") or bucket ("4xx", "5xx"). */
    fun matchStatus(status: Int?, filter: String?): Boolean {
        if (filter.isNullOrEmpty()) return true
        if (status == null) return false
        if (filter.length == 3 && filter.endsWith("xx", ignoreCase = true)) {
            val bucket = filter[0].digitToIntOrNull() ?: return false
            return status / 100 == bucket
        }
        return status.toString() == filter
    }

    /** search: treat as a regex over [text]; a malformed regex matches nothing (never throws). */
    fun matchSearch(text: String, regex: String?): Boolean {
        if (regex.isNullOrEmpty()) return true
        return runCatching { Regex(regex).containsMatchIn(text) }.getOrDefault(false)
    }

    private val SEVERITY_RANK = mapOf(
        "false_positive" to -1, "information" to 0, "info" to 0, "low" to 1, "medium" to 2, "high" to 3,
    )
    private val CONFIDENCE_RANK = mapOf("tentative" to 0, "firm" to 1, "certain" to 2)

    fun severityAtLeast(severity: String, min: String?): Boolean =
        rankAtLeast(severity, min, SEVERITY_RANK)

    fun confidenceAtLeast(confidence: String, min: String?): Boolean =
        rankAtLeast(confidence, min, CONFIDENCE_RANK)

    private fun rankAtLeast(value: String, min: String?, ranks: Map<String, Int>): Boolean {
        if (min.isNullOrEmpty()) return true
        val minRank = ranks[min.lowercase()] ?: return true
        val valRank = ranks[value.lowercase()] ?: return true
        return valRank >= minRank
    }
}
