package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.Serializable
import java.util.concurrent.atomic.AtomicInteger

@Serializable
data class SendResult(val id: String, val status: Int?, val responseLength: Int, val mimeType: String? = null, val note: String)

@Serializable
data class CookieListResult(val cookies: List<CookieDTO>)

@Serializable
data class ScopeResult(val url: String, val action: String, val ok: Boolean = true)

@Serializable
data class InterceptResult(val interceptEnabled: Boolean)

@Serializable
data class IssueCreateResult(val created: Boolean, val note: String)

/**
 * Mutating / outbound tools. Every one is marked `mutating = true`, so the [ToolRegistry] gates it behind the
 * unsafe master switch on the wire path; those that send/define targets are additionally scope-checked here
 * BEFORE any Montoya object is built, when scopeOnly is on.
 */
class ActionTools(
    private val actions: BurpActions,
    private val registry: MessageRegistry,
    private val scopeOnly: () -> Boolean,
    private val isInScope: (String) -> Boolean,
) {
    private val sendCounter = AtomicInteger(0)

    fun build(): List<ToolSpec> = listOf(
        httpSend(),
        repeaterCreateTab(),
        intruderSend(),
        scopeInclude(),
        scopeExclude(),
        proxyIntercept(),
        cookieJarGet(),
        cookieSet(),
        issueCreate(),
        sitemapAdd(),
    )

    private fun sitemapAdd(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", Descriptions.RAW_REQUEST, required = true)
            targetSchema(this)
            string("responseRaw", "Optional raw HTTP response to attach. " + Descriptions.RAW_RESPONSE)
        }
        return ToolSpec("sitemap_add", "Add to site map", "Insert a request/response into Burp's site map (e.g. a discovered endpoint).", "Site Map", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = resolvePort(args, secure)
            scopeReject(baseUrl(host, port, secure))?.let { return@ToolSpec it }
            actions.addToSiteMap(args.require("content"), host, port, secure, args.str("responseRaw"))
            Results.text("Added request to the site map for $host:$port.")
        }
    }

    private fun targetSchema(b: SchemaBuilder.Builder) {
        b.string("host", Descriptions.TARGET_HOST, required = true)
        b.integer("port", Descriptions.TARGET_PORT)
        b.boolean("secure", Descriptions.TARGET_SECURE, default = true)
    }

    private fun resolvePort(args: Args, secure: Boolean) = args.int("port") ?: if (secure) 443 else 80

    private fun baseUrl(host: String, port: Int, secure: Boolean): String {
        val scheme = if (secure) "https" else "http"
        val portPart = if ((secure && port == 443) || (!secure && port == 80)) "" else ":$port"
        return "$scheme://$host$portPart/"
    }

    private fun scopeReject(url: String): CallToolResult? =
        if (scopeOnly() && !isInScope(url)) {
            Results.error("Blocked: $url is out of scope and scope-confinement is enabled.")
        } else {
            null
        }

    // ---- http_send ----

    private fun httpSend(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", Descriptions.RAW_REQUEST, required = true)
            targetSchema(this)
            string("httpMode", "Protocol mode.", enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send", "Send HTTP request", DESC_SEND, "Requests", schema, mutating = true) { args ->
            val host = args.require("host")
            val secure = args.boolOr("secure", true)
            val port = resolvePort(args, secure)
            scopeReject(baseUrl(host, port, secure))?.let { return@ToolSpec it }
            val sent = actions.sendRequest(args.require("content"), host, port, secure, args.strOr("httpMode", "auto"))
            val id = "send:${sendCounter.incrementAndGet()}"
            registry.put(MessageRegistry.Handle(id, sent.mimeType, { sent.requestBytes }, { sent.responseBytes }))
            Results.structured(
                SendResult.serializer(),
                SendResult(
                    id = id, status = sent.statusCode, responseLength = sent.responseBytes?.size ?: 0, mimeType = sent.mimeType,
                    note = "Fetch the response with get_http_message id=$id part=response section=body.",
                ),
            )
        }
    }

    // ---- repeater / intruder ----

    private fun repeaterCreateTab(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", Descriptions.RAW_REQUEST, required = true)
            targetSchema(this)
            string("tabName", "Optional Repeater tab caption.")
        }
        return ToolSpec("repeater_create_tab", "Send to Repeater", "Create a Repeater tab for a request (not auto-sent).", "Requests", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = resolvePort(args, secure)
            scopeReject(baseUrl(host, port, secure))?.let { return@ToolSpec it }
            actions.sendToRepeater(args.require("content"), host, port, secure, args.str("tabName"))
            Results.text("Created a Repeater tab for $host:$port.")
        }
    }

    private fun intruderSend(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", Descriptions.RAW_REQUEST, required = true)
            targetSchema(this)
            string("name", "Optional Intruder tab name.")
        }
        return ToolSpec("intruder_send", "Send to Intruder", "Send a request to Intruder (populates a tab; not auto-started).", "Requests", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = resolvePort(args, secure)
            scopeReject(baseUrl(host, port, secure))?.let { return@ToolSpec it }
            actions.sendToIntruder(args.require("content"), host, port, secure, args.str("name"))
            Results.text("Sent to Intruder for $host:$port.")
        }
    }

    // ---- scope ----

    private fun scopeInclude(): ToolSpec {
        val schema = SchemaBuilder.build { string("url", "URL/prefix to add to target scope.", required = true) }
        return ToolSpec("scope_include", "Include in scope", "Add a URL prefix to Burp's target scope.", "Scope", schema, mutating = true) { args ->
            val url = args.require("url"); actions.includeInScope(url)
            Results.structured(ScopeResult.serializer(), ScopeResult(url, "include"))
        }
    }

    private fun scopeExclude(): ToolSpec {
        val schema = SchemaBuilder.build { string("url", "URL/prefix to remove from target scope.", required = true) }
        return ToolSpec("scope_exclude", "Exclude from scope", "Remove a URL prefix from Burp's target scope.", "Scope", schema, mutating = true) { args ->
            val url = args.require("url"); actions.excludeFromScope(url)
            Results.structured(ScopeResult.serializer(), ScopeResult(url, "exclude"))
        }
    }

    // ---- proxy intercept ----

    private fun proxyIntercept(): ToolSpec {
        val schema = SchemaBuilder.build { boolean("enabled", "Turn proxy intercept on or off.", default = false) }
        return ToolSpec("proxy_intercept", "Toggle proxy intercept", "Enable or disable Burp Proxy intercept.", "Proxy", schema, mutating = true) { args ->
            actions.setIntercept(args.boolOr("enabled", false))
            Results.structured(InterceptResult.serializer(), InterceptResult(actions.isInterceptEnabled()))
        }
    }

    // ---- cookies ----

    private fun cookieJarGet(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("domain", "Filter by domain substring.")
            boolean("includeValues", "Include cookie values (otherwise redacted).", default = false)
        }
        return ToolSpec("cookie_jar_get", "Get cookie jar", "List Burp's cookie jar entries (values redacted by default).", "Config", schema) { args ->
            val domain = args.str("domain"); val includeValues = args.boolOr("includeValues", false)
            val cookies = actions.cookies()
                .filter { domain.isNullOrEmpty() || it.domain.contains(domain, ignoreCase = true) }
                .map { if (includeValues) it else it.copy(value = "[REDACTED]") }
            Results.structured(CookieListResult.serializer(), CookieListResult(cookies))
        }
    }

    private fun cookieSet(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("name", "Cookie name.", required = true)
            string("value", "Cookie value.", required = true)
            string("domain", "Cookie domain.", required = true)
            string("path", "Cookie path.", default = "/")
            integer("expiresEpochSec", "Expiry as unix seconds (default +1 year).")
        }
        return ToolSpec("cookie_set", "Set cookie", "Add/replace a cookie in Burp's cookie jar.", "Config", schema, mutating = true) { args ->
            actions.setCookie(args.require("name"), args.require("value"), args.require("domain"), args.str("path"), args.int("expiresEpochSec")?.toLong())
            Results.text("Cookie '${args.require("name")}' set for ${args.require("domain")}.")
        }
    }

    // ---- issue_create ----

    private fun issueCreate(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("name", "Issue name.", required = true)
            string("detail", "Issue detail / description.", required = true)
            string("severity", "Severity.", enum = listOf("high", "medium", "low", "information"), default = "information")
            string("confidence", "Confidence.", enum = listOf("certain", "firm", "tentative"), default = "tentative")
            string("baseUrl", "Affected base URL.", required = true)
            string("remediation", "Remediation guidance.", default = "")
            string("background", "Background.", default = "")
            targetSchema(this)
            string("requestRaw", "Optional raw HTTP request evidence. " + Descriptions.RAW_REQUEST)
            string("responseRaw", "Optional raw HTTP response evidence. " + Descriptions.RAW_RESPONSE)
        }
        return ToolSpec("issue_create", "Create issue", DESC_ISSUE, "Issues", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = resolvePort(args, secure)
            val created = actions.createIssue(
                NewIssue(
                    name = args.require("name"), detail = args.require("detail"),
                    remediation = args.strOr("remediation", ""), baseUrl = args.require("baseUrl"),
                    severity = args.strOr("severity", "information"), confidence = args.strOr("confidence", "tentative"),
                    background = args.strOr("background", ""), host = host, port = port, secure = secure,
                    requestRaw = args.str("requestRaw"), responseRaw = args.str("responseRaw"),
                ),
            )
            Results.structured(
                IssueCreateResult.serializer(),
                IssueCreateResult(created, if (created) "Issue added to the site map." else "Skipped: a matching issue already exists."),
            )
        }
    }

    companion object {
        private const val DESC_SEND =
            "Send a raw HTTP request and get back the status + a handle id; fetch the response body via get_http_message. " +
                "Respects scope confinement. This is the workhorse for agent request/response round-trips."
        private const val DESC_ISSUE =
            "Register a custom issue in Burp's site map (e.g. ingesting an external scanner finding). De-duplicates on name+baseUrl."
    }
}
