package com.revoltsecurities.burpmcp.tools

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Paths

class ReportPathTest {

    private val base = Paths.get("/home/u/.revolt-mcp/reports")

    @Test
    fun `strips traversal and forces extension`() {
        val p = ReportPath.resolve("../../etc/passwd", "html", base)
        assertEquals(base.resolve("passwd.html"), p)
        assertTrue(p.startsWith(base))
    }

    @Test
    fun `keeps a clean name and matches xml`() {
        assertEquals(base.resolve("scan.xml"), ReportPath.resolve("scan", "xml", base))
        assertEquals(base.resolve("scan.xml"), ReportPath.resolve("scan.xml", "xml", base))
    }

    @Test
    fun `empty name falls back to report`() {
        assertEquals(base.resolve("report.html"), ReportPath.resolve("", "html", base))
    }
}

class JsEndpointsTest {

    @Test
    fun `extracts urls and paths and drops asset junk`() {
        val js = """
            var api = "/api/v1/users"; fetch("https://x.com/data?id=1");
            const img = "/logo.png"; const r = "assets/app.js"; let q = '/';
        """.trimIndent()
        val out = JsEndpoints.extract(js)
        assertTrue(out.contains("/api/v1/users"))
        assertTrue(out.any { it.startsWith("https://x.com/data") })
        assertFalse(out.contains("/logo.png")) // asset junk filtered
        assertFalse(out.contains("/")) // bare slash filtered
    }
}

private class FakeScanner : BurpScanner {
    var lastCrawlSeeds: List<String>? = null
    private val tasks = linkedMapOf<String, String>()
    override fun startCrawl(seedUrls: List<String>): ScanStartResult {
        lastCrawlSeeds = seedUrls; tasks["scan:1"] = "crawl"; return ScanStartResult("scan:1", "crawl", "ok")
    }
    override fun startAudit(active: Boolean, requests: List<RawTarget>): ScanStartResult {
        tasks["scan:2"] = "audit"; return ScanStartResult("scan:2", "audit", "ok")
    }
    override fun taskStatus(taskId: String): ScanTaskStatus? =
        if (tasks.containsKey(taskId)) ScanTaskStatus(taskId, tasks[taskId]!!, 5, 0, 3, 1, "running") else null
    override fun listTasks(): List<ScanTaskInfo> = tasks.map { ScanTaskInfo(it.key, it.value, "t") }
    override fun deleteTask(taskId: String): Boolean = tasks.remove(taskId) != null
    override fun generateReport(taskId: String?, format: String, userPath: String): ReportResult =
        ReportResult("/tmp/$userPath.$format", 2, format)
}

private class FakeCollaborator : BurpCollaborator {
    val saved = mutableListOf<String>()
    var lastPollKey: String? = null
    override fun generate(customData: String?): CollaboratorPayloadInfo {
        saved += "sk-123"
        return CollaboratorPayloadInfo("abc.oast.site", "iid", "sk-123", "note")
    }
    override fun poll(secretKey: String?, includeHttp: Boolean, interactionId: String?): CollaboratorPollResult {
        lastPollKey = secretKey
        // null key = poll all saved; mimic the real impl returning one interaction per saved client.
        val count = if (secretKey != null) 1 else saved.size
        return CollaboratorPollResult(
            interactions = List(count) { InteractionDTO("iid", "DNS", "t", "1.2.3.4", "cd", null) },
            clientsPolled = count,
            note = "polled",
        )
    }
}

private class FakeSource(private val exchanges: List<HttpExchange>) : BurpDataSource {
    override fun proxyHistory() = exchanges
    override fun webSocketHistory() = emptyList<WebSocketRecord>()
    override fun siteMap() = emptyList<SiteMapNode>()
    override fun issues() = emptyList<IssueRecord>()
    override fun isInScope(url: String) = true
    override fun burpVersion() = "x"
    override fun burpEdition() = "PROFESSIONAL"
    override fun isProfessional() = true
}

class ScanToolsTest {

    private val scanner = FakeScanner()
    private val collab = FakeCollaborator()
    private val source = FakeSource(
        listOf(
            HttpExchange(0, "GET", "https://x.com/app.js", "x.com", 200, "application/javascript", 1, 1, null, true,
                { ByteArray(0) }, { """var u="/api/secret";""".toByteArray() }),
        ),
    )
    private val tools = ScanTools(scanner, collab, source, ScopeGuard({ false }, { true })).build().associateBy { it.id }

    private fun call(id: String, args: Map<String, Any?>) = runBlocking {
        tools.getValue(id).handler(
            Args(
                buildJsonObject {
                    args.forEach { (k, v) ->
                        when (v) {
                            is String -> put(k, JsonPrimitive(v))
                            is Int -> put(k, JsonPrimitive(v))
                            is Boolean -> put(k, JsonPrimitive(v))
                            else -> {}
                        }
                    }
                },
            ),
        )
    }

    @Test
    fun `scan tools are professional-gated and scan starts are mutating`() {
        assertTrue(tools.getValue("scan_crawl_start").proOnly)
        assertTrue(tools.getValue("scan_crawl_start").mutating)
        assertTrue(tools.getValue("collaborator_generate").proOnly)
        assertFalse(tools.getValue("extract_js_endpoints").proOnly)
        assertFalse(tools.getValue("collaborator_poll").mutating)
    }

    @Test
    fun `crawl start parses seed list`() {
        call("scan_crawl_start", mapOf("seedUrls" to "https://a.com, https://b.com\nhttps://c.com"))
        assertEquals(listOf("https://a.com", "https://b.com", "https://c.com"), scanner.lastCrawlSeeds)
    }

    @Test
    fun `task status round trip`() {
        call("scan_crawl_start", mapOf("seedUrls" to "https://a.com"))
        val res = call("scan_task_status", mapOf("taskId" to "scan:1"))
        val st = Results.json.decodeFromJsonElement(ScanTaskStatus.serializer(), res.structuredContent!!)
        assertEquals("crawl", st.type)
        assertEquals(5, st.requestCount)
    }

    @Test
    fun `collaborator generate and poll`() {
        val g = call("collaborator_generate", emptyMap())
        val info = Results.json.decodeFromJsonElement(CollaboratorPayloadInfo.serializer(), g.structuredContent!!)
        assertEquals("sk-123", info.secretKey)
        val p = call("collaborator_poll", mapOf("secretKey" to "sk-123"))
        val poll = Results.json.decodeFromJsonElement(CollaboratorPollResult.serializer(), p.structuredContent!!)
        assertEquals(1, poll.interactions.size)
        assertEquals("DNS", poll.interactions.first().type)
    }

    @Test
    fun `collaborator poll works with no secretKey (polls all saved)`() {
        call("collaborator_generate", emptyMap())
        val p = call("collaborator_poll", emptyMap()) // no secretKey
        val poll = Results.json.decodeFromJsonElement(CollaboratorPollResult.serializer(), p.structuredContent!!)
        assertEquals(null, collab.lastPollKey) // polled all, not a specific key
        assertTrue(poll.interactions.isNotEmpty())
    }

    @Test
    fun `extract_js_endpoints harvests with source and line attribution`() {
        val res = call("extract_js_endpoints", mapOf("inScopeOnly" to false))
        val r = Results.json.decodeFromJsonElement(JsEndpointsResult.serializer(), res.structuredContent!!)
        val hit = r.endpoints.firstOrNull { it.endpoint == "/api/secret" }
        assertTrue(hit != null)
        assertEquals("https://x.com/app.js", hit!!.source)
        assertEquals("ph:0", hit.messageId)
        assertEquals(1, hit.line)
    }
}
