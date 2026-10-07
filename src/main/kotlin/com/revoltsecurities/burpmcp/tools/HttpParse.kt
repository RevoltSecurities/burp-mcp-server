package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

@Serializable
data class HttpHeaderKV(val name: String, val value: String)

@Serializable
data class ParsedRequest(
    val method: String,
    val target: String,
    val httpVersion: String,
    val headers: List<HttpHeaderKV>,
    val bodyLength: Int,
    val body: String? = null,
)

@Serializable
data class ParsedResponse(
    val httpVersion: String,
    val statusCode: Int?,
    val reason: String,
    val headers: List<HttpHeaderKV>,
    val bodyLength: Int,
    val body: String? = null,
)

@Serializable
data class ReflectedParam(val name: String, val value: String, val source: String, val reflections: Int)

/**
 * Pure raw-HTTP parsing and analysis. Works on request/response text so it is Montoya-free and unit-testable;
 * the tools feed it bytes fetched from the client (not from Burp), e.g. a request the agent is crafting.
 */
object HttpParse {

    fun parseRequest(raw: String, includeBody: Boolean): ParsedRequest {
        val (head, body) = splitHeadBody(raw)
        val lines = head.split("\r\n", "\n")
        val requestLine = lines.firstOrNull().orEmpty().split(" ")
        val method = requestLine.getOrElse(0) { "" }
        val target = requestLine.getOrElse(1) { "" }
        val version = requestLine.getOrElse(2) { "" }
        return ParsedRequest(
            method = method,
            target = target,
            httpVersion = version,
            headers = parseHeaders(lines.drop(1)),
            bodyLength = body.length,
            body = if (includeBody) body else null,
        )
    }

    fun parseResponse(raw: String, includeBody: Boolean): ParsedResponse {
        val (head, body) = splitHeadBody(raw)
        val lines = head.split("\r\n", "\n")
        val statusLine = lines.firstOrNull().orEmpty().split(" ", limit = 3)
        val version = statusLine.getOrElse(0) { "" }
        val code = statusLine.getOrNull(1)?.toIntOrNull()
        val reason = statusLine.getOrElse(2) { "" }
        return ParsedResponse(
            httpVersion = version,
            statusCode = code,
            reason = reason,
            headers = parseHeaders(lines.drop(1)),
            bodyLength = body.length,
            body = if (includeBody) body else null,
        )
    }

    /** Extract request parameters from the query string and (form) body. */
    fun extractParams(raw: String): List<ReflectedParam> {
        val parsed = parseRequest(raw, includeBody = true)
        val out = mutableListOf<ReflectedParam>()
        val query = parsed.target.substringAfter('?', "")
        out += parsePairs(query, "query")
        val contentType = parsed.headers.firstOrNull { it.name.equals("Content-Type", true) }?.value ?: ""
        if (contentType.contains("application/x-www-form-urlencoded")) {
            out += parsePairs(parsed.body.orEmpty(), "body")
        }
        return out
    }

    /** Count how often each request parameter value is reflected verbatim in the response. */
    fun findReflected(rawRequest: String, rawResponse: String): List<ReflectedParam> {
        val params = extractParams(rawRequest)
        val (_, respBody) = splitHeadBody(rawResponse)
        return params.mapNotNull { p ->
            if (p.value.length < 3) return@mapNotNull null
            val count = countOccurrences(respBody, p.value)
            if (count > 0) p.copy(reflections = count) else null
        }
    }

    /** Minimal line-oriented diff (added/removed) between two texts. */
    fun diff(a: String, b: String): String {
        val al = a.split("\n")
        val bl = b.split("\n")
        val bSet = bl.toHashSet()
        val aSet = al.toHashSet()
        val sb = StringBuilder()
        al.filter { it !in bSet }.forEach { sb.appendLine("- $it") }
        bl.filter { it !in aSet }.forEach { sb.appendLine("+ $it") }
        return sb.toString().ifEmpty { "(no line differences)" }
    }

    private fun parseHeaders(lines: List<String>): List<HttpHeaderKV> =
        lines.filter { it.isNotBlank() }.mapNotNull { line ->
            val idx = line.indexOf(':')
            if (idx <= 0) null else HttpHeaderKV(line.substring(0, idx).trim(), line.substring(idx + 1).trim())
        }

    private fun parsePairs(encoded: String, source: String): List<ReflectedParam> =
        encoded.split("&").filter { it.isNotEmpty() }.map {
            val name = it.substringBefore('=')
            val value = runCatching { java.net.URLDecoder.decode(it.substringAfter('=', ""), Charsets.UTF_8) }.getOrDefault("")
            ReflectedParam(name, value, source, 0)
        }

    private fun splitHeadBody(raw: String): Pair<String, String> {
        val crlf = raw.indexOf("\r\n\r\n")
        if (crlf >= 0) return raw.substring(0, crlf) to raw.substring(crlf + 4)
        val lf = raw.indexOf("\n\n")
        return if (lf >= 0) raw.substring(0, lf) to raw.substring(lf + 2) else raw to ""
    }

    private fun countOccurrences(haystack: String, needle: String): Int {
        if (needle.isEmpty()) return 0
        var count = 0
        var idx = haystack.indexOf(needle)
        while (idx >= 0) {
            count++
            idx = haystack.indexOf(needle, idx + needle.length)
        }
        return count
    }
}
