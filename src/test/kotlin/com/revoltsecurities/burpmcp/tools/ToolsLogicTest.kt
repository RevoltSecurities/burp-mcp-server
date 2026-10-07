package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.ByteBudget
import com.revoltsecurities.burpmcp.output.PageEnvelope
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PagerTest {

    private data class Item(val n: Int)

    private fun pageOf(all: List<Item>, limit: Int, cursor: String?, maxBytes: Int = 10_000) =
        Pager.page(
            all = all, keyOf = { Pager.intKey(it.n) }, ordering = "n",
            cursor = cursor, filterHash = "fh", limit = limit, maxBytes = maxBytes,
            toRow = { it.n }, measure = { 4 },
        )

    @Test
    fun `numeric keys sort correctly as strings`() {
        assertTrue(Pager.intKey(9) < Pager.intKey(10))
    }

    @Test
    fun `paginates via cursor across pages`() {
        val all = (1..5).map { Item(it) }
        val p1 = pageOf(all, limit = 2, cursor = null)
        assertEquals(listOf(1, 2), p1.items)
        assertTrue(p1.hasMore)
        assertNotNull(p1.nextCursor)
        assertEquals(5, p1.totalCount)

        val p2 = pageOf(all, limit = 2, cursor = p1.nextCursor)
        assertEquals(listOf(3, 4), p2.items)
        val p3 = pageOf(all, limit = 2, cursor = p2.nextCursor)
        assertEquals(listOf(5), p3.items)
        assertFalse(p3.hasMore)
        assertNull(p3.nextCursor)
    }

    @Test
    fun `byte budget shortens a page and sets a cursor`() {
        val all = (1..10).map { Item(it) }
        // measure=4 bytes each; budget 10 keeps ~2-3 then stops.
        val page = pageOf(all, limit = 10, cursor = null, maxBytes = 10)
        assertTrue(page.items.size < 10)
        assertTrue(page.hasMore)
        assertNotNull(page.nextCursor)
        assertNotNull(page.truncation)
    }
}

class FiltersTest {

    @Test
    fun `status exact and bucket matching`() {
        assertTrue(Filters.matchStatus(404, "404"))
        assertFalse(Filters.matchStatus(404, "200"))
        assertTrue(Filters.matchStatus(404, "4xx"))
        assertTrue(Filters.matchStatus(503, "5xx"))
        assertFalse(Filters.matchStatus(200, "4xx"))
        assertFalse(Filters.matchStatus(null, "200"))
        assertTrue(Filters.matchStatus(200, null))
    }

    @Test
    fun `severity minimum`() {
        assertTrue(Filters.severityAtLeast("HIGH", "medium"))
        assertTrue(Filters.severityAtLeast("MEDIUM", "medium"))
        assertFalse(Filters.severityAtLeast("LOW", "high"))
        assertTrue(Filters.severityAtLeast("LOW", null))
    }

    @Test
    fun `host and search`() {
        assertTrue(Filters.matchHost("api.example.com", "example"))
        assertFalse(Filters.matchHost("api.example.com", "other"))
        assertTrue(Filters.matchSearch("/users/42", "users/\\d+"))
        assertFalse(Filters.matchSearch("/x", "users"))
        assertFalse(Filters.matchSearch("/x", "[invalid")) // malformed regex never throws and matches nothing
    }
}

class CodecsTest {

    @Test
    fun `url and base64 round trips`() {
        assertEquals("a+b%26c", Codecs.urlEncode("a b&c")) // URLEncoder uses + for space
        assertEquals("a b&c", Codecs.urlDecode("a+b%26c"))
        assertEquals("hello", Codecs.base64Decode(Codecs.base64Encode("hello")))
    }

    @Test
    fun `sha256 known value`() {
        assertEquals(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            Codecs.hash("sha256", "hello"),
        )
    }

    @Test
    fun `jwt decode extracts payload`() {
        // {"alg":"HS256"} . {"sub":"123"} . sig
        val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
        val decoded = Codecs.jwtDecode(jwt)
        assertTrue(decoded.contains("\"sub\":\"123\""))
    }

    @Test
    fun `deflate roundtrip`() {
        val input = "hello deflate world ".repeat(5)
        val d = java.util.zip.Deflater().apply { setInput(input.toByteArray()); finish() }
        val buf = ByteArray(4096); val n = d.deflate(buf); d.end()
        val b64 = java.util.Base64.getEncoder().encodeToString(buf.copyOf(n))
        assertEquals(input, Codecs.decodeAs(b64, "deflate"))
    }
}

/** Regression for the duplicate-URL site-map pagination/id bug (reviewer C1/H1). */
class SiteMapDupKeyTest {

    private fun node(i: Int, status: Int) = SiteMapNode(
        index = i, url = "https://x.com/dup", host = "x.com", method = "GET", statusCode = status,
        mimeType = "text/html", responseLength = 5, inScope = true,
        requestBytes = { "GET /dup HTTP/1.1\r\nHost: x.com\r\n\r\n".toByteArray() },
        responseBytes = { "HTTP/1.1 $status X\r\nContent-Type: text/html\r\n\r\nBODY$i-$status".toByteArray() },
    )

    private val source = object : BurpDataSource {
        override fun proxyHistory() = emptyList<HttpExchange>()
        override fun webSocketHistory() = emptyList<WebSocketRecord>()
        override fun siteMap() = listOf(node(0, 200), node(1, 302), node(2, 500))
        override fun issues() = emptyList<IssueRecord>()
        override fun isInScope(url: String) = true
        override fun burpVersion() = "x"; override fun burpEdition() = "PROFESSIONAL"; override fun isProfessional() = true
    }

    private val registry = com.revoltsecurities.burpmcp.output.MessageRegistry()
    private val cfg = ToolConfig(50, 100, 96_000, 8_192, 65_536)
    private val siteMapTool = ReadTools(source, registry, cfg).build().first { it.id == "get_site_map" }
    private val getMsg = com.revoltsecurities.burpmcp.tools.HttpMessageTool.build(registry, cfg)

    private fun page(cursor: String?) = kotlinx.coroutines.runBlocking {
        val res = siteMapTool.handler(
            Args(
                buildJsonObject {
                    put("inScopeOnly", JsonPrimitive(false)); put("limit", JsonPrimitive(2))
                    if (cursor != null) put("cursor", JsonPrimitive(cursor))
                },
            ),
        )
        Results.json.decodeFromJsonElement(PageEnvelope.serializer(SiteMapRow.serializer()), res.structuredContent!!)
    }

    @Test
    fun `duplicate URLs are not dropped across pages and ids are distinct`() {
        val p1 = page(null)
        assertEquals(2, p1.items.size)
        assertTrue(p1.hasMore)
        val p2 = page(p1.nextCursor)
        assertEquals(1, p2.items.size)
        val ids = (p1.items + p2.items).map { it.id }
        assertEquals(3, ids.size)
        assertEquals(3, ids.toSet().size) // all distinct — no id collision
    }

    @Test
    fun `each row id resolves to its own response bytes`() {
        val rows = page(null).items + page(page(null).nextCursor).items
        val bodies = rows.map { row ->
            kotlinx.coroutines.runBlocking {
                val r = getMsg.handler(Args(buildJsonObject { put("id", JsonPrimitive(row.id)); put("part", JsonPrimitive("response")); put("section", JsonPrimitive("body")) }))
                Results.json.decodeFromJsonElement(HttpMessageResult.serializer(), r.structuredContent!!).content
            }
        }
        // three distinct responses, not the same one three times (the H1 collision bug)
        assertEquals(3, bodies.toSet().size)
    }
}

class ByteBudgetMeasureTest {
    @Test
    fun `utf8 size counts bytes not chars`() {
        assertEquals(1, ByteBudget.utf8Size("a"))
        assertEquals(2, ByteBudget.utf8Size("é"))
    }
}

/** End-to-end over the tool handler with a fake data source (no Montoya). */
class ReadToolsEndToEndTest {

    private fun exchange(i: Int, host: String, status: Int, body: String) = HttpExchange(
        index = i, method = "GET", url = "https://$host/p$i", host = host, statusCode = status,
        mimeType = "text/html", requestLength = 10, responseLength = body.length, notes = null, inScope = true,
        requestBytes = { "GET /p$i HTTP/1.1\r\nHost: $host\r\n\r\n".toByteArray() },
        responseBytes = { "HTTP/1.1 $status OK\r\nContent-Type: text/html\r\n\r\n$body".toByteArray() },
    )

    private val source = object : BurpDataSource {
        override fun proxyHistory() = listOf(
            exchange(0, "a.com", 200, "hello-a"),
            exchange(1, "b.com", 404, "not-found"),
            exchange(2, "a.com", 500, "boom"),
        )
        override fun webSocketHistory() = emptyList<WebSocketRecord>()
        override fun siteMap() = emptyList<SiteMapNode>()
        override fun issues() = emptyList<IssueRecord>()
        override fun isInScope(url: String) = true
        override fun burpVersion() = "Burp 2026.7"
        override fun burpEdition() = "PROFESSIONAL"
        override fun isProfessional() = true
    }

    private val registry = com.revoltsecurities.burpmcp.output.MessageRegistry()
    private val cfg = ToolConfig(50, 100, 96_000, 8_192, 65_536)
    private val tools = ReadTools(source, registry, cfg).build().associateBy { it.id }

    private fun call(id: String, args: Map<String, Any?>) = kotlinx.coroutines.runBlocking {
        val json = kotlinx.serialization.json.buildJsonObject {
            args.forEach { (k, v) ->
                when (v) {
                    is String -> put(k, kotlinx.serialization.json.JsonPrimitive(v))
                    is Int -> put(k, kotlinx.serialization.json.JsonPrimitive(v))
                    is Boolean -> put(k, kotlinx.serialization.json.JsonPrimitive(v))
                    null -> {}
                    else -> put(k, kotlinx.serialization.json.JsonPrimitive(v.toString()))
                }
            }
        }
        tools.getValue(id).handler(Args(json))
    }

    @Test
    fun `proxy history returns typed rows without bodies and filters by status`() {
        val result = call("get_proxy_http_history", mapOf("status" to "5xx"))
        val obj = result.structuredContent!!
        val env = Results.json.decodeFromJsonElement(PageEnvelope.serializer(ProxyHistoryRow.serializer()), obj)
        assertEquals(1, env.items.size)
        val row = env.items.first()
        assertEquals(500, row.status)
        assertEquals("a.com", row.host)
        assertEquals("ph:2", row.id)
        // rows must not contain bodies
        assertFalse(Results.json.encodeToString(ProxyHistoryRow.serializer(), row).contains("boom"))
    }

    @Test
    fun `host filter narrows results`() {
        val result = call("get_proxy_http_history", mapOf("host" to "a.com"))
        val env = Results.json.decodeFromJsonElement(
            PageEnvelope.serializer(ProxyHistoryRow.serializer()), result.structuredContent!!,
        )
        assertEquals(2, env.items.size)
    }

    @Test
    fun `get_http_message resolves a row id and slices the body`() {
        // populate the registry by listing first
        call("get_proxy_http_history", emptyMap())
        val getMsg = com.revoltsecurities.burpmcp.tools.HttpMessageTool.build(registry, cfg)
        val res = kotlinx.coroutines.runBlocking {
            getMsg.handler(
                Args(
                    kotlinx.serialization.json.buildJsonObject {
                        put("id", kotlinx.serialization.json.JsonPrimitive("ph:0"))
                        put("part", kotlinx.serialization.json.JsonPrimitive("response"))
                        put("section", kotlinx.serialization.json.JsonPrimitive("body"))
                    },
                ),
            )
        }
        val msg = Results.json.decodeFromJsonElement(HttpMessageResult.serializer(), res.structuredContent!!)
        assertEquals("ph:0", msg.id)
        assertEquals("hello-a", msg.content)
        assertEquals("utf8", msg.bodyEncoding)
    }
}
