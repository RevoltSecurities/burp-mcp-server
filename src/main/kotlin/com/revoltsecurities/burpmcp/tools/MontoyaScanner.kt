package com.revoltsecurities.burpmcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.ReportFormat
import burp.api.montoya.scanner.Crawl as MontoyaCrawl
import burp.api.montoya.scanner.audit.Audit as MontoyaAudit
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** Montoya-backed [BurpScanner]; owns the live Crawl/Audit task objects. Professional-only. */
class MontoyaScanner(private val api: MontoyaApi) : BurpScanner {

    private class Entry(
        val id: String,
        val type: String,
        val target: String,
        val crawl: MontoyaCrawl?,
        val audit: MontoyaAudit?,
    )

    private val tasks = ConcurrentHashMap<String, Entry>()
    private val counter = AtomicInteger(0)

    override fun startCrawl(seedUrls: List<String>): ScanStartResult {
        require(seedUrls.isNotEmpty()) { "At least one seed URL is required" }
        val crawl = api.scanner().startCrawl(CrawlConfiguration.crawlConfiguration(*seedUrls.toTypedArray()))
        val id = nextId()
        tasks[id] = Entry(id, "crawl", seedUrls.joinToString(", ").take(200), crawl, null)
        return ScanStartResult(id, "crawl", "Crawl started with ${seedUrls.size} seed(s). Poll with scan_task_status taskId=$id.")
    }

    override fun startAudit(active: Boolean, requests: List<RawTarget>): ScanStartResult {
        val cfg = AuditConfiguration.auditConfiguration(
            if (active) BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS else BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS,
        )
        val audit = api.scanner().startAudit(cfg)
        requests.forEach {
            runCatching { audit.addRequest(HttpRequest.httpRequest(HttpService.httpService(it.host, it.port, it.secure), it.raw)) }
        }
        val id = nextId()
        tasks[id] = Entry(id, "audit", "${requests.size} request(s), ${if (active) "active" else "passive"}", null, audit)
        return ScanStartResult(id, "audit", "Audit started (${requests.size} request(s)). Poll with scan_task_status taskId=$id.")
    }

    override fun taskStatus(taskId: String): ScanTaskStatus? {
        val e = tasks[taskId] ?: return null
        return if (e.crawl != null) {
            ScanTaskStatus(e.id, "crawl", safe { e.crawl.requestCount() }, safe { e.crawl.errorCount() }, null, 0, msg { e.crawl.statusMessage() })
        } else {
            val a = e.audit!!
            ScanTaskStatus(e.id, "audit", safe { a.requestCount() }, safe { a.errorCount() }, safe { a.insertionPointCount() }, safe { a.issues().size }, msg { a.statusMessage() })
        }
    }

    override fun listTasks(): List<ScanTaskInfo> = tasks.values.map { ScanTaskInfo(it.id, it.type, it.target) }

    override fun deleteTask(taskId: String): Boolean {
        val e = tasks.remove(taskId) ?: return false
        runCatching { e.crawl?.delete() }
        runCatching { e.audit?.delete() }
        return true
    }

    override fun generateReport(taskId: String?, format: String, userPath: String): ReportResult {
        val issues = if (taskId != null && taskId != "all") {
            tasks[taskId]?.audit?.issues() ?: api.siteMap().issues()
        } else {
            api.siteMap().issues()
        }
        val fmt = if (format.equals("xml", ignoreCase = true)) ReportFormat.XML else ReportFormat.HTML
        val base = ReportPath.defaultBaseDir()
        Files.createDirectories(base)
        val path = ReportPath.resolve(userPath, format, base)
        api.scanner().generateReport(issues, fmt, path)
        return ReportResult(path.toString(), issues.size, if (fmt == ReportFormat.XML) "xml" else "html")
    }

    private fun nextId() = "scan:${counter.incrementAndGet()}"
    private fun safe(block: () -> Int): Int = runCatching(block).getOrDefault(0)
    private fun msg(block: () -> String?): String = runCatching(block).getOrNull().orEmpty()
}
