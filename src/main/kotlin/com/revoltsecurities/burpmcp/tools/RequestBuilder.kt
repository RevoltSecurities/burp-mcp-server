package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Assembles a byte-correct raw HTTP request from STRUCTURED fields (method / host / url / path / headers /
 * body + bodyType / httpVersion), so an agent never has to hand-write a raw request string. This removes the
 * whole class of malformed-request bugs: a missing Host header, a wrong/ absent Content-Length, a missing
 * Content-Type for the body shape, or CRLF mistakes. The connection target (host/port/secure) is resolved
 * deterministically here too, so the scope check always has a host. Montoya-free → unit-tested.
 *
 * NOTE: the standard send tools (`http_send`, `http_send_analyze`, `http_send_compare`, `intruder_send`,
 * `repeater_create_tab`, `sitemap_add`, `organizer_send`) take STRUCTURED fields ONLY — the raw `content`
 * parameter was removed from their schemas in v1.1.0 so a model cannot hand-write a malformed request. Byte-exact
 * raw requests live only on the race/intruder tools (`raw_request` / `raw_requests` / `template`), which send
 * verbatim and do not go through this builder.
 */
object RequestBuilder {

    private val json = Json

    /** The assembled request plus its resolved connection target. */
    data class Built(val raw: String, val host: String, val port: Int, val secure: Boolean)

    /**
     * Build from an [Args] bag (the send tools' arguments). Throws [IllegalArgumentException] with an
     * agent-actionable message when the inputs are insufficient or a typed body is malformed.
     */
    fun fromArgs(args: Args): Built = buildFromFields(
        method = args.strOr("method", "GET"),
        url = args.str("url"),
        host = args.str("host"),
        port = args.int("port"),
        secure = args.bool("secure"),
        path = args.str("path"),
        httpVersion = args.strOr("httpVersion", "HTTP/1.1"),
        headers = args.strList("headers"),
        body = args.str("body"),
        bodyType = args.str("bodyType"),
    )

    /**
     * Per-side build for two-request tools (e.g. http_send_compare): each field is read as `<name><suffix>`
     * (e.g. `methodA`, `bodyB`) and falls back to the shared un-suffixed field. host/port/secure/headers are
     * shared across both sides (same target).
     */
    fun fromArgsSide(args: Args, suffix: String): Built = buildFromFields(
        method = args.str("method$suffix") ?: args.strOr("method", "GET"),
        url = args.str("url$suffix") ?: args.str("url"),
        host = args.str("host"),
        port = args.int("port"),
        secure = args.bool("secure"),
        path = args.str("path$suffix") ?: args.str("path"),
        httpVersion = args.str("httpVersion$suffix") ?: args.strOr("httpVersion", "HTTP/1.1"),
        headers = args.strList("headers"),
        body = args.str("body$suffix") ?: args.str("body"),
        bodyType = args.str("bodyType$suffix") ?: args.str("bodyType"),
    )

    private fun buildFromFields(
        method: String,
        url: String?,
        host: String?,
        port: Int?,
        secure: Boolean?,
        path: String?,
        httpVersion: String,
        headers: List<String>,
        body: String?,
        bodyType: String?,
    ): Built {
        val m = method.trim().uppercase()
        val version = normalizeVersion(httpVersion)
        val bt = bodyType?.trim()?.lowercase()
        val hostR: String
        val portR: Int
        val secureR: Boolean
        val pathR: String
        if (url != null) {
            val uri = runCatching { java.net.URI(url.trim()) }.getOrNull()
                ?: throw IllegalArgumentException("Invalid url '$url'.")
            hostR = uri.host ?: throw IllegalArgumentException("url '$url' has no host.")
            secureR = secure ?: uri.scheme.equals("https", ignoreCase = true)
            portR = port ?: uri.port.takeIf { it > 0 } ?: if (secureR) 443 else 80
            val q = uri.rawQuery?.let { "?$it" } ?: ""
            pathR = (uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/") + q
        } else {
            hostR = host
                ?: throw IllegalArgumentException("A structured request needs 'host' (or a full 'url'). Pass host, or provide raw 'content'.")
            secureR = secure ?: true
            portR = port ?: if (secureR) 443 else 80
            pathR = normalizePath(path)
        }
        val raw = build(m, pathR, hostR, portR, secureR, version, headers, body, bt)
        return Built(raw, hostR, portR, secureR)
    }

    /** Assemble the raw request text (CRLF line endings, Host present, Content-Type + Content-Length set). */
    fun build(
        method: String,
        path: String,
        host: String,
        port: Int,
        secure: Boolean,
        httpVersion: String,
        headers: List<String>,
        body: String?,
        bodyType: String?,
    ): String {
        require(method.isNotBlank()) { "method must not be blank." }
        val target = normalizePath(path)

        // Ordered, case-insensitive header map so the agent's headers win but we can fill defaults.
        val ordered = LinkedHashMap<String, Pair<String, String>>() // lowerName -> (name, value)
        fun set(name: String, value: String) { ordered[name.lowercase()] = name to value }
        fun has(name: String) = ordered.containsKey(name.lowercase())

        // Host first (include the port only when non-default for the scheme).
        val hostHeader = if ((secure && port != 443) || (!secure && port != 80)) "$host:$port" else host
        set("Host", hostHeader)

        // The formatted body + its default content type.
        val formatted = formatBody(body, bodyType)
        if (formatted != null && formatted.contentType != null) set("Content-Type", formatted.contentType)

        // Caller headers (override Host/Content-Type if they supplied them explicitly).
        for (line in headers) {
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            val n = line.substring(0, idx).trim()
            val v = line.substring(idx + 1).trim()
            if (n.isNotEmpty()) set(n, v)
        }

        val bodyText = formatted?.text
        if (bodyText != null) {
            // Always (re)compute Content-Length so it can never disagree with the body — a classic cause of
            // hangs / 400s. Drop any Transfer-Encoding the caller set, which would conflict.
            ordered.remove("transfer-encoding")
            set("Content-Length", bodyText.toByteArray(Charsets.UTF_8).size.toString())
        } else if (!has("content-length") && method in METHODS_WITH_OPTIONAL_BODY) {
            // No body on a method that may carry one: be explicit so servers that expect it don't wait.
            set("Content-Length", "0")
        }

        val sb = StringBuilder()
        sb.append(method).append(' ').append(target).append(' ').append(httpVersion).append("\r\n")
        for ((_, nv) in ordered) sb.append(nv.first).append(": ").append(nv.second).append("\r\n")
        sb.append("\r\n")
        if (bodyText != null) sb.append(bodyText)
        return sb.toString()
    }

    private data class FormattedBody(val text: String, val contentType: String?)

    private fun formatBody(body: String?, bodyType: String?): FormattedBody? {
        if (body == null) return null
        return when (bodyType) {
            null, "", "raw", "text" -> FormattedBody(body, null) // caller owns Content-Type via headers
            "json" -> {
                validateJson(body)
                FormattedBody(body, "application/json")
            }
            "graphql" -> {
                // Accept a full {query,variables} object as-is, or wrap a bare query string into one.
                val text = if (body.trimStart().startsWith("{")) {
                    validateJson(body); body
                } else {
                    json.encodeToString(kotlinx.serialization.json.JsonObject.serializer(), buildJsonObject { put("query", body) })
                }
                FormattedBody(text, "application/json")
            }
            "form", "urlencoded" -> FormattedBody(body, "application/x-www-form-urlencoded")
            "soap", "soapxml", "soap+xml" -> FormattedBody(body, "application/soap+xml; charset=utf-8")
            "xml" -> FormattedBody(body, "application/xml")
            else -> throw IllegalArgumentException("Unknown bodyType '$bodyType'. Use json, graphql, form, xml, soapxml, or raw.")
        }
    }

    private fun validateJson(body: String) {
        runCatching { json.parseToJsonElement(body) }.getOrElse {
            throw IllegalArgumentException("body is not valid JSON (bodyType=json/graphql): ${it.message}")
        }
    }

    /** Ensure the request target starts with '/'. An absolute-URL target is left intact (proxy form). */
    private fun normalizePath(path: String?): String {
        val p = path?.trim().takeUnless { it.isNullOrEmpty() } ?: return "/"
        if (p.startsWith("http://", true) || p.startsWith("https://", true)) return p
        return if (p.startsWith("/")) p else "/$p"
    }

    /** Normalize a user-supplied HTTP version token to "HTTP/1.1" or "HTTP/2". */
    private fun normalizeVersion(v: String): String {
        val s = v.trim().lowercase().removePrefix("http/").removePrefix("http")
        return if (s.startsWith("2")) "HTTP/2" else "HTTP/1.1"
    }

    private val METHODS_WITH_OPTIONAL_BODY = setOf("POST", "PUT", "PATCH", "DELETE")
}

/** Shared schema fields for the structured request builder — the send tools' primary (and only agent-facing)
 *  way to specify a request. Pair with the host/port/secure target fields. */
fun SchemaBuilder.Builder.structuredRequestParams() {
    string("method", Descriptions.BUILD_METHOD, default = "GET")
    string("url", Descriptions.BUILD_URL)
    string("path", Descriptions.BUILD_PATH)
    stringArray("headers", Descriptions.REQUEST_HEADERS)
    string("body", Descriptions.BUILD_BODY)
    string("bodyType", Descriptions.BUILD_BODY_TYPE, enum = listOf("json", "graphql", "form", "xml", "soapxml", "raw"))
    string("httpVersion", Descriptions.BUILD_HTTP_VERSION, enum = listOf("HTTP/1.1", "HTTP/2"), default = "HTTP/1.1")
}

/** Per-side structured fields for two-request tools (http_send_compare). host/port/secure/headers are shared. */
fun SchemaBuilder.Builder.structuredRequestParamsSuffixed(suffix: String) {
    string("method$suffix", "HTTP method for request $suffix (structured). Default GET.", default = "GET")
    string("url$suffix", "Full URL for request $suffix (alternative to the shared 'host' + 'path$suffix').")
    string("path$suffix", "Path (+query) for request $suffix when using the shared 'host', e.g. \"/users/1\". Default \"/\".")
    string("body$suffix", "Body for request $suffix (pair with 'bodyType$suffix').")
    string("bodyType$suffix", "Body type for request $suffix.", enum = listOf("json", "graphql", "form", "xml", "soapxml", "raw"))
}
