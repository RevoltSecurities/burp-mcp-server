package com.revoltsecurities.burpmcp.tools

/**
 * Pure endpoint harvesting from JS/HTML/text bodies — paths and URLs an agent can then crawl/audit.
 * There is no Montoya "find JS endpoints" API, so we regex it.
 */
object JsEndpoints {

    private val ABSOLUTE_URL = Regex("""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+""")
    private val QUOTED_PATH = Regex("""["'`](/[A-Za-z0-9._~/\-]{1,256})["'`]""")
    private val QUOTED_REL = Regex("""["'`]([A-Za-z0-9_\-]+(?:/[A-Za-z0-9._~\-]+)+)["'`]""")

    private val JUNK = Regex("""^[/.]*$|\.(png|jpe?g|gif|svg|ico|css|woff2?|ttf|map)$""", RegexOption.IGNORE_CASE)

    /** One extracted endpoint with the 1-based line number it was found on. */
    data class Match(val endpoint: String, val line: Int)

    fun extract(body: String): Set<String> = extractWithLines(body).map { it.endpoint }.toCollection(LinkedHashSet())

    /** Extract endpoints with source line numbers; de-duplicated keeping the first occurrence (earliest line). */
    fun extractWithLines(body: String): List<Match> {
        val lineStarts = lineStartOffsets(body)
        val out = LinkedHashMap<String, Int>() // endpoint -> first line
        fun record(value: String, offset: Int) {
            if (value.length in 2..512 && !JUNK.containsMatchIn(value) && !out.containsKey(value)) {
                out[value] = lineOf(offset, lineStarts)
            }
        }
        ABSOLUTE_URL.findAll(body).forEach { record(it.value.trimEnd('\\', '"', '\'', ')', ',', ';'), it.range.first) }
        QUOTED_PATH.findAll(body).forEach { record(it.groupValues[1], it.range.first) }
        QUOTED_REL.findAll(body).forEach { record(it.groupValues[1], it.range.first) }
        return out.map { Match(it.key, it.value) }
    }

    private fun lineStartOffsets(body: String): IntArray {
        val starts = ArrayList<Int>()
        starts.add(0)
        var i = body.indexOf('\n')
        while (i >= 0) { starts.add(i + 1); i = body.indexOf('\n', i + 1) }
        return starts.toIntArray()
    }

    private fun lineOf(offset: Int, lineStarts: IntArray): Int {
        // binary search: largest lineStart <= offset → that 0-based line, +1 for 1-based.
        var lo = 0; var hi = lineStarts.size - 1; var ans = 0
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (lineStarts[mid] <= offset) { ans = mid; lo = mid + 1 } else hi = mid - 1
        }
        return ans + 1
    }
}
