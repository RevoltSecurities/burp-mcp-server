package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

@Serializable
data class JsEndpointsResult(val endpoints: List<String>, val count: Int, val scanned: Int, val truncated: Boolean)

/**
 * Scanner / crawler / Collaborator automation + recon (Professional for the scan/collab tools). Drives
 * Burp's own crawl & audit, exports reports, and verifies OOB — so an agent can run recon → audit → verify →
 * report. Scan-start / delete / report / collaborator-generate are mutating (unsafe-gated on the wire path).
 */
class ScanTools(
    private val scanner: BurpScanner,
    private val collaborator: BurpCollaborator,
    private val dataSource: BurpDataSource,
    private val maxEndpoints: Int = 300,
    private val maxResponsesScanned: Int = 300,
) {
    fun build(): List<ToolSpec> = listOf(
        crawlStart(),
        auditStart(),
        taskStatus(),
        taskList(),
        taskDelete(),
        report(),
        collaboratorGenerate(),
        collaboratorPoll(),
        extractJsEndpoints(),
    )

    private fun crawlStart(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("seedUrls", "One or more ABSOLUTE seed URLs to crawl (include scheme), separated by comma/space/newline. Example: \"https://example.com/ https://example.com/app\".", required = true)
        }
        return ToolSpec("scan_crawl_start", "Start crawl", "Start a Burp crawl from seed URLs; poll progress with scan_task_status.", "Scanner", schema, mutating = true, proOnly = true) { args ->
            val seeds = splitList(args.require("seedUrls"))
            if (seeds.isEmpty()) return@ToolSpec Results.error("Provide at least one seed URL.")
            Results.structured(ScanStartResult.serializer(), scanner.startCrawl(seeds))
        }
    }

    private fun auditStart(): ToolSpec {
        val schema = SchemaBuilder.build {
            boolean("active", "Active audit (true) or passive (false).", default = true)
            string("content", "Optional single raw HTTP request to seed the audit. " + Descriptions.RAW_REQUEST)
            string("host", "Target host for the seed request; REQUIRED when content is given. " + Descriptions.TARGET_HOST)
            integer("port", "Target port (default 443 if secure else 80).")
            boolean("secure", "Use TLS.", default = true)
        }
        return ToolSpec("scan_audit_start", "Start audit", "Start a Burp audit (active/passive), optionally seeded with a request; poll with scan_task_status.", "Scanner", schema, mutating = true, proOnly = true) { args ->
            val content = args.str("content")
            val requests = if (content != null) {
                val host = args.str("host") ?: return@ToolSpec Results.error("host is required when content is provided.")
                val secure = args.boolOr("secure", true)
                listOf(RawTarget(content, host, args.int("port") ?: if (secure) 443 else 80, secure))
            } else {
                emptyList()
            }
            Results.structured(ScanStartResult.serializer(), scanner.startAudit(args.boolOr("active", true), requests))
        }
    }

    private fun taskStatus(): ToolSpec {
        val schema = SchemaBuilder.build { string("taskId", "Scan task id returned by scan_crawl_start/scan_audit_start (e.g. \"scan:1\"). List them with scan_task_list.", required = true) }
        return ToolSpec("scan_task_status", "Scan task status", "Report a scan task's progress and issue count.", "Scanner", schema, proOnly = true) { args ->
            val id = args.require("taskId")
            scanner.taskStatus(id)?.let { Results.structured(ScanTaskStatus.serializer(), it) }
                ?: Results.error("Unknown task '$id'. Use scan_task_list.")
        }
    }

    private fun taskList(): ToolSpec =
        ToolSpec("scan_task_list", "List scan tasks", "List active crawl/audit tasks.", "Scanner", SchemaBuilder.empty(), proOnly = true) {
            Results.structured(ScanTaskList.serializer(), ScanTaskList(scanner.listTasks()))
        }

    private fun taskDelete(): ToolSpec {
        val schema = SchemaBuilder.build { string("taskId", "Scan task id to delete.", required = true) }
        return ToolSpec("scan_task_delete", "Delete scan task", "Delete/cancel a scan task.", "Scanner", schema, mutating = true, proOnly = true) { args ->
            val id = args.require("taskId")
            if (scanner.deleteTask(id)) Results.text("Deleted $id.") else Results.error("Unknown task '$id'.")
        }
    }

    private fun report(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("taskId", "Audit task id to report on, or 'all' for every site-map issue.", default = "all")
            string("format", "Report format.", enum = listOf("html", "xml"), default = "html")
            string("path", "Report filename (saved under ~/.revolt-mcp/reports).", default = "report")
        }
        return ToolSpec("scan_report", "Generate report", "Generate an HTML/XML scan report (sandboxed to the reports directory).", "Scanner", schema, mutating = true, proOnly = true) { args ->
            Results.structured(ReportResult.serializer(), scanner.generateReport(args.str("taskId"), args.strOr("format", "html"), args.strOr("path", "report")))
        }
    }

    private fun collaboratorGenerate(): ToolSpec {
        val schema = SchemaBuilder.build { string("customData", "Optional correlation data (<=16 alnum).") }
        return ToolSpec("collaborator_generate", "Generate Collaborator payload", "Generate a Burp Collaborator payload for OOB/blind detection; poll later with collaborator_poll.", "Collaborator", schema, mutating = true, proOnly = true) { args ->
            Results.structured(CollaboratorPayloadInfo.serializer(), collaborator.generate(args.str("customData")))
        }
    }

    private fun collaboratorPoll(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("secretKey", "The secretKey returned by a prior collaborator_generate call.", required = true)
            boolean("includeHttp", "Register HTTP interaction evidence for get_http_message.", default = false)
        }
        return ToolSpec("collaborator_poll", "Poll Collaborator", "Poll Collaborator interactions (DNS/HTTP/SMTP) for a prior payload.", "Collaborator", schema, proOnly = true) { args ->
            Results.structured(CollaboratorPollResult.serializer(), collaborator.poll(args.require("secretKey"), args.boolOr("includeHttp", false)))
        }
    }

    private fun extractJsEndpoints(): ToolSpec {
        val schema = SchemaBuilder.build {
            boolean("inScopeOnly", "Only scan in-scope responses.", default = true)
            integer("limit", "Max endpoints to return.", default = maxEndpoints, minimum = 1, maximum = maxEndpoints)
        }
        return ToolSpec("extract_js_endpoints", "Extract JS endpoints", "Harvest URLs/paths from JS/HTML response bodies in proxy history + site map.", "Recon", schema) { args ->
            val inScopeOnly = args.boolOr("inScopeOnly", true)
            val limit = args.intOr("limit", maxEndpoints).coerceIn(1, maxEndpoints)
            val found = LinkedHashSet<String>()
            var scanned = 0
            val responses = buildList {
                dataSource.proxyHistory().forEach { if (!inScopeOnly || it.inScope) add(it.responseBytes) }
                dataSource.siteMap().forEach { if (!inScopeOnly || it.inScope) add(it.responseBytes) }
            }
            for (provider in responses) {
                if (scanned >= maxResponsesScanned || found.size >= limit) break
                val bytes = runCatching { provider() }.getOrNull() ?: continue
                scanned++
                found += JsEndpoints.extract(String(bytes, Charsets.UTF_8))
            }
            val list = found.take(limit)
            Results.structured(JsEndpointsResult.serializer(), JsEndpointsResult(list, list.size, scanned, found.size > limit))
        }
    }

    private fun splitList(s: String): List<String> =
        s.split(',', ' ', '\n', '\t', '\r').map { it.trim() }.filter { it.isNotEmpty() }
}
