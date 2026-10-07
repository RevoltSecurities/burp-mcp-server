package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import com.revoltsecurities.burpmcp.output.PageEnvelope
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.Serializable

@Serializable
data class ScopeCheckResult(val url: String, val inScope: Boolean)

@Serializable
data class BurpVersionResult(val version: String, val edition: String, val professional: Boolean)

@Serializable
data class WsRow(val index: Int, val url: String, val host: String, val direction: String, val length: Int)

/**
 * Read-only tools over [BurpDataSource], all on the Phase-2 output model (typed rows + keyset cursors +
 * byte budget). Bodies are never embedded; each list registers byte handles so `get_http_message` can
 * resolve a row's `id`.
 */
class ReadTools(
    private val source: BurpDataSource,
    private val registry: MessageRegistry,
    private val cfg: ToolConfig,
) {
    fun build(): List<ToolSpec> = listOf(
        proxyHttpHistory(),
        siteMap(),
        scannerIssues(),
        webSocketHistory(),
        scopeCheck(),
        burpVersion(),
    )

    private fun limitOf(args: Args) = args.intOr("limit", cfg.defaultLimit).coerceIn(1, cfg.maxLimit)

    // ---- proxy_http_history ----

    private fun proxyHttpHistory(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("host", Descriptions.HOST_FILTER)
            string("method", "Filter by HTTP method, exact & case-insensitive (e.g. \"GET\", \"POST\"). Omit for all.")
            string("status", Descriptions.STATUS_FILTER)
            string("mimeType", "Filter by response MIME, case-insensitive substring (e.g. \"json\", \"html\"). Omit for all.")
            boolean("inScopeOnly", Descriptions.IN_SCOPE_ONLY, default = true)
            string("search", Descriptions.SEARCH_REGEX)
            integer("limit", "Max rows per page (server cap ${cfg.maxLimit}).", default = cfg.defaultLimit, minimum = 1, maximum = cfg.maxLimit)
            string("cursor", Descriptions.CURSOR)
        }
        return ToolSpec("get_proxy_http_history", "Proxy HTTP history", DESC_HISTORY, "History", schema) { args ->
            val host = args.str("host"); val method = args.str("method"); val status = args.str("status")
            val mime = args.str("mimeType"); val inScopeOnly = args.boolOr("inScopeOnly", true); val search = args.str("search")
            val filterHash = com.revoltsecurities.burpmcp.output.CursorCodec.filterHash(
                mapOf("host" to host, "method" to method, "status" to status, "mime" to mime,
                    "scope" to inScopeOnly.toString(), "search" to search),
            )
            val filtered = source.proxyHistory().filter {
                (!inScopeOnly || it.inScope) &&
                    Filters.matchHost(it.host, host) && Filters.matchMethod(it.method, method) &&
                    Filters.matchStatus(it.statusCode, status) && Filters.matchMime(it.mimeType, mime) &&
                    Filters.matchSearch(it.url, search)
            }
            val page = Pager.page(
                all = filtered, keyOf = { Pager.intKey(it.index) }, ordering = "index",
                cursor = args.str("cursor"), filterHash = filterHash, limit = limitOf(args),
                maxBytes = cfg.maxToolResultBytes,
                toRow = { e -> registerExchange(e); e.toRow() },
                measure = { estimate(ProxyHistoryRow.serializer(), it) },
            )
            Results.structured(PageEnvelope.serializer(ProxyHistoryRow.serializer()), page)
        }
    }

    // ---- site_map ----

    private fun siteMap(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("host", Descriptions.HOST_FILTER)
            string("pathPrefix", "Only URLs whose path starts with this prefix, e.g. \"/api/\".")
            string("mimeType", "Filter by response MIME, case-insensitive substring (e.g. \"json\").")
            boolean("inScopeOnly", Descriptions.IN_SCOPE_ONLY, default = true)
            string("search", Descriptions.SEARCH_REGEX)
            integer("limit", "Max rows per page (server cap ${cfg.maxLimit}).", default = cfg.defaultLimit, minimum = 1, maximum = cfg.maxLimit)
            string("cursor", Descriptions.CURSOR)
        }
        return ToolSpec("get_site_map", "Site map", DESC_SITEMAP, "Site Map", schema) { args ->
            val host = args.str("host"); val prefix = args.str("pathPrefix"); val mime = args.str("mimeType")
            val inScopeOnly = args.boolOr("inScopeOnly", true); val search = args.str("search")
            val filterHash = com.revoltsecurities.burpmcp.output.CursorCodec.filterHash(
                mapOf("host" to host, "prefix" to prefix, "mime" to mime, "scope" to inScopeOnly.toString(), "search" to search),
            )
            val filtered = source.siteMap().filter {
                (!inScopeOnly || it.inScope) &&
                    Filters.matchHost(it.host, host) && Filters.matchMime(it.mimeType, mime) &&
                    Filters.matchSearch(it.url, search) &&
                    (prefix.isNullOrEmpty() || pathOf(it.url).startsWith(prefix))
            }
            val page = Pager.page(
                all = filtered, keyOf = { it.url }, ordering = "url",
                cursor = args.str("cursor"), filterHash = filterHash, limit = limitOf(args),
                maxBytes = cfg.maxToolResultBytes,
                toRow = { n -> registerNode(n); n.toRow() },
                measure = { estimate(SiteMapRow.serializer(), it) },
            )
            Results.structured(PageEnvelope.serializer(SiteMapRow.serializer()), page)
        }
    }

    // ---- scanner_issues (Pro) ----

    private fun scannerIssues(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("severity", "Minimum severity.", enum = listOf("information", "low", "medium", "high"))
            string("confidence", "Minimum confidence.", enum = listOf("tentative", "firm", "certain"))
            string("host", Descriptions.HOST_FILTER)
            string("definitionId", "Filter by issue definition name, case-insensitive substring.")
            string("search", "Optional regex matched against the issue name.")
            integer("limit", "Max rows per page (server cap ${cfg.maxLimit}).", default = cfg.defaultLimit, minimum = 1, maximum = cfg.maxLimit)
            string("cursor", Descriptions.CURSOR)
        }
        return ToolSpec("get_scanner_issues", "Scanner issues", DESC_ISSUES, "Scanner", schema, proOnly = true) { args ->
            val sev = args.str("severity"); val conf = args.str("confidence"); val host = args.str("host")
            val defId = args.str("definitionId"); val search = args.str("search")
            val filterHash = com.revoltsecurities.burpmcp.output.CursorCodec.filterHash(
                mapOf("sev" to sev, "conf" to conf, "host" to host, "def" to defId, "search" to search),
            )
            val filtered = source.issues().filter {
                Filters.severityAtLeast(it.severity, sev) && Filters.confidenceAtLeast(it.confidence, conf) &&
                    Filters.matchHost(it.host, host) && Filters.matchSearch(it.name, search) &&
                    (defId.isNullOrEmpty() || (it.definitionId?.contains(defId, ignoreCase = true) == true))
            }
            val page = Pager.page(
                all = filtered, keyOf = { Pager.intKey(it.index) }, ordering = "index",
                cursor = args.str("cursor"), filterHash = filterHash, limit = limitOf(args),
                maxBytes = cfg.maxToolResultBytes,
                toRow = { i -> registerIssue(i); i.toRow() },
                measure = { estimate(IssueRow.serializer(), it) },
            )
            Results.structured(PageEnvelope.serializer(IssueRow.serializer()), page)
        }
    }

    // ---- ws history ----

    private fun webSocketHistory(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("host", Descriptions.HOST_FILTER)
            integer("limit", "Max rows per page (server cap ${cfg.maxLimit}).", default = cfg.defaultLimit, minimum = 1, maximum = cfg.maxLimit)
            string("cursor", Descriptions.CURSOR)
        }
        return ToolSpec("get_proxy_ws_history", "Proxy WebSocket history", DESC_WS, "History", schema) { args ->
            val host = args.str("host")
            val filterHash = com.revoltsecurities.burpmcp.output.CursorCodec.filterHash(mapOf("host" to host))
            val filtered = source.webSocketHistory().filter { Filters.matchHost(it.host, host) }
            val page = Pager.page(
                all = filtered, keyOf = { Pager.intKey(it.index) }, ordering = "index",
                cursor = args.str("cursor"), filterHash = filterHash, limit = limitOf(args),
                maxBytes = cfg.maxToolResultBytes,
                toRow = { WsRow(it.index, it.url, it.host, it.direction, it.length) },
                measure = { estimate(WsRow.serializer(), it) },
            )
            Results.structured(PageEnvelope.serializer(WsRow.serializer()), page)
        }
    }

    // ---- scope_check ----

    private fun scopeCheck(): ToolSpec {
        val schema = SchemaBuilder.build { string("url", "Absolute URL to test against Burp's target scope.", required = true) }
        return ToolSpec("scope_check", "Scope check", "Return whether a URL is in Burp's target scope.", "Scope", schema) { args ->
            val url = args.require("url")
            Results.structured(ScopeCheckResult.serializer(), ScopeCheckResult(url, source.isInScope(url)))
        }
    }

    // ---- burp_version ----

    private fun burpVersion(): ToolSpec =
        ToolSpec("burp_version", "Burp version", "Report Burp Suite version, edition, and whether Professional features are available.", "Config", SchemaBuilder.empty()) {
            Results.structured(
                BurpVersionResult.serializer(),
                BurpVersionResult(source.burpVersion(), source.burpEdition(), source.isProfessional()),
            )
        }

    // ---- helpers ----

    private fun registerExchange(e: HttpExchange) = registry.put(
        MessageRegistry.Handle(MessageRegistry.proxyHistoryId(e.index), e.mimeType, e.requestBytes, e.responseBytes),
    )

    private fun registerNode(n: SiteMapNode) = registry.put(
        MessageRegistry.Handle(MessageRegistry.siteMapId(n.url), n.mimeType, n.requestBytes, n.responseBytes),
    )

    private fun registerIssue(i: IssueRecord) = registry.put(
        MessageRegistry.Handle(
            MessageRegistry.issueId(i.index), null,
            i.firstEvidenceRequest ?: { null }, i.firstEvidenceResponse ?: { null },
        ),
    )

    private fun <T> estimate(serializer: kotlinx.serialization.KSerializer<T>, value: T): Int =
        Results.json.encodeToString(serializer, value).toByteArray(Charsets.UTF_8).size

    private fun pathOf(url: String): String =
        runCatching { java.net.URI(url).path ?: "/" }.getOrDefault("/")

    companion object {
        private const val DESC_HISTORY =
            "List proxy HTTP history as typed metadata rows (no bodies). Filter by host/method/status/mime/scope/search; " +
                "paginate with cursor. Fetch a row's bytes with get_http_message using the row id."
        private const val DESC_SITEMAP =
            "List site-map entries as typed rows (no bodies). Filter by host/pathPrefix/mime/scope/search; paginate with cursor."
        private const val DESC_ISSUES =
            "List scanner issues as typed rows (Professional). Filter by min severity/confidence, host, definition, search; " +
                "get full detail/evidence via get_issue_detail or get_http_message with the issue id."
        private const val DESC_WS =
            "List proxy WebSocket messages as typed rows. Filter by host; paginate with cursor."
    }
}
