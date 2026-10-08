package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

/** The id/name/function/location header parsed from a .bambda document. */
@Serializable
data class BambdaMeta(
    val id: String? = null,
    val name: String? = null,
    val function: String? = null,
    val location: String? = null,
)

/**
 * Pure helpers for Burp Bambda documents. A `.bambda` is a YAML-ish header (id/name/function/location) plus a
 * `source: |+` block holding the Java body — `api.bambda().importBambda(String)` takes the WHOLE document, so a
 * bare Java snippet is rejected with "function required / location required". [assemble] builds a valid document
 * from structured parts; [parseMeta] reads an existing one. Montoya-free → unit-tested.
 */
object BambdaDoc {

    /** Bambda `function:` values (what the snippet returns / does). */
    val FUNCTIONS = listOf(
        "VIEW_FILTER", "CUSTOM_COLUMN", "CUSTOM_ACTION",
        "MATCH_AND_REPLACE_REQUEST", "MATCH_AND_REPLACE_RESPONSE", "SCAN_CHECK_PASSIVE_PER_REQUEST",
    )

    /** Bambda `location:` values (the Burp context it runs in). */
    val LOCATIONS = listOf(
        "PROXY_HTTP_HISTORY", "PROXY_WEBSOCKET", "REPEATER", "SCANNER", "LOGGER", "SITE_MAP",
    )

    /** True if [text] already looks like a full document (has the function/location/source header). */
    fun looksLikeDocument(text: String): Boolean =
        Regex("(?m)^\\s*function\\s*:").containsMatchIn(text) &&
            Regex("(?m)^\\s*location\\s*:").containsMatchIn(text) &&
            Regex("(?m)^\\s*source\\s*:").containsMatchIn(text)

    /**
     * Build a valid `.bambda` document from parts. [source] is the Java body (with or without a leading
     * `/** … @author … **/` comment); it is placed under a `source: |+` block, indented 2 spaces.
     */
    fun assemble(name: String, function: String, location: String, source: String): String {
        val body = source.trim('\n')
        val indented = body.split("\n").joinToString("\n") { if (it.isEmpty()) "" else "  $it" }
        return buildString {
            append("id: ").append(java.util.UUID.randomUUID()).append('\n')
            append("name: ").append(name.ifBlank { "Untitled" }).append('\n')
            append("function: ").append(function).append('\n')
            append("location: ").append(location).append('\n')
            append("source: |+\n")
            append(indented).append('\n')
        }
    }

    /** Parse the header of a .bambda document (everything before the `source:` line). */
    fun parseMeta(document: String): BambdaMeta {
        val head = document.substringBefore("\nsource:").substringBefore("source:")
        fun v(key: String): String? =
            Regex("(?m)^\\s*$key\\s*:\\s*(.+)$").find(head)?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotEmpty() }
        return BambdaMeta(v("id"), v("name"), v("function"), v("location"))
    }
}
