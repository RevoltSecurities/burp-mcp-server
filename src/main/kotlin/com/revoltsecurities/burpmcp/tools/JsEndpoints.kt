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

    fun extract(body: String): Set<String> {
        val out = LinkedHashSet<String>()
        ABSOLUTE_URL.findAll(body).forEach { out += it.value.trimEnd('\\', '"', '\'', ')', ',', ';') }
        QUOTED_PATH.findAll(body).forEach { out += it.groupValues[1] }
        QUOTED_REL.findAll(body).forEach { out += it.groupValues[1] }
        return out.filter { it.length in 2..512 && !JUNK.containsMatchIn(it) }.toCollection(LinkedHashSet())
    }
}
