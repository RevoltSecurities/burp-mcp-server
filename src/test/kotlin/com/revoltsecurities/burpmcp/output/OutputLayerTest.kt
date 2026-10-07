package com.revoltsecurities.burpmcp.output

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CursorCodecTest {

    @Test
    fun `round trips key and ordering when filter hash matches`() {
        val fh = CursorCodec.filterHash(mapOf("host" to "example.com", "status" to "200"))
        val cursor = CursorCodec.encode(lastKey = "42", filterHash = fh, ordering = "index")
        val pos = CursorCodec.decode(cursor, fh)
        assertEquals("42", pos.lastKey)
        assertEquals("index", pos.ordering)
    }

    @Test
    fun `rejects cursor issued for a different filter set`() {
        val fhA = CursorCodec.filterHash(mapOf("host" to "a.com"))
        val fhB = CursorCodec.filterHash(mapOf("host" to "b.com"))
        val cursor = CursorCodec.encode("10", fhA, "index")
        assertThrows(CursorCodec.InvalidCursorException::class.java) { CursorCodec.decode(cursor, fhB) }
    }

    @Test
    fun `rejects malformed cursor`() {
        val fh = CursorCodec.filterHash(emptyMap())
        assertThrows(CursorCodec.InvalidCursorException::class.java) { CursorCodec.decode("not-a-cursor!!", fh) }
    }

    @Test
    fun `filter hash is order-independent and ignores nulls`() {
        val a = CursorCodec.filterHash(mapOf("host" to "x", "method" to "GET", "mime" to null))
        val b = CursorCodec.filterHash(mapOf("method" to "GET", "host" to "x"))
        assertEquals(a, b)
    }
}

class ByteBudgetTest {

    @Test
    fun `keeps everything within budget`() {
        val fit = ByteBudget.fit(listOf("aa", "bb", "cc"), maxBytes = 100) { it.length }
        assertEquals(3, fit.kept.size)
        assertEquals(0, fit.droppedCount)
        assertFalse(fit.truncated)
    }

    @Test
    fun `drops tail when budget exceeded and reports count`() {
        val items = List(10) { "xxxx" } // 4 bytes each
        val fit = ByteBudget.fit(items, maxBytes = 10) { it.length }
        assertTrue(fit.truncated)
        assertEquals(items.size, fit.kept.size + fit.droppedCount)
        assertTrue(fit.usedBytes <= 10)
    }

    @Test
    fun `always keeps at least one oversized item for progress`() {
        val fit = ByteBudget.fit(listOf("this-single-item-is-huge"), maxBytes = 2) { it.length }
        assertEquals(1, fit.kept.size)
        assertEquals(0, fit.droppedCount)
    }
}

class BodySlicerTest {

    private val hint: (Int) -> String = { next -> "get_http_message offset=$next" }

    @Test
    fun `slices a window and emits a resumable truncation marker`() {
        val body = "0123456789".toByteArray()
        val slice = BodySlicer.slice(body, offset = 0, length = 4, mimeType = "text/plain", maxLength = 8, continuationHint = hint)
        assertEquals("0123", slice.content)
        assertEquals(BodySlicer.Encoding.UTF8, slice.encoding)
        assertNotNull(slice.truncation)
        assertEquals(6L, slice.truncation!!.bytesOmitted)
        assertEquals("get_http_message offset=4", slice.truncation.nextAction)
    }

    @Test
    fun `no truncation when window covers the whole body`() {
        val body = "hello".toByteArray()
        val slice = BodySlicer.slice(body, offset = 0, length = 100, mimeType = "text/plain", maxLength = 100, continuationHint = hint)
        assertEquals("hello", slice.content)
        assertNull(slice.truncation)
    }

    @Test
    fun `length is capped by maxLength`() {
        val body = "0123456789".toByteArray()
        val slice = BodySlicer.slice(body, offset = 0, length = 100, mimeType = "text/plain", maxLength = 3, continuationHint = hint)
        assertEquals("012", slice.content)
        assertEquals(3, slice.length)
        assertNotNull(slice.truncation)
    }

    @Test
    fun `binary content is omitted not inlined`() {
        val body = ByteArray(5000) { 1 }
        val slice = BodySlicer.slice(body, offset = 0, length = 8192, mimeType = "image/png", maxLength = 8192, continuationHint = hint)
        assertEquals(BodySlicer.Encoding.OMITTED, slice.encoding)
        assertEquals("", slice.content)
        assertEquals(5000, slice.totalBytes)
        assertTrue(slice.truncation!!.reason.contains("Binary"))
    }

    @Test
    fun `content type classification`() {
        assertTrue(BodySlicer.isBinary("image/png"))
        assertTrue(BodySlicer.isBinary("application/octet-stream"))
        assertTrue(BodySlicer.isBinary("application/pdf"))
        assertFalse(BodySlicer.isBinary("text/html; charset=utf-8"))
        assertFalse(BodySlicer.isBinary("application/json"))
        assertFalse(BodySlicer.isBinary("application/vnd.api+json"))
        assertFalse(BodySlicer.isBinary(null))
    }
}

class MessageRegistryTest {

    @Test
    fun `put and get round trip with lazy providers`() {
        val reg = MessageRegistry()
        var called = false
        reg.put(
            MessageRegistry.Handle(
                id = MessageRegistry.proxyHistoryId(7),
                mimeType = "text/html",
                requestBytes = { "req".toByteArray() },
                responseBytes = { called = true; "resp".toByteArray() },
            ),
        )
        val handle = reg.get("ph:7")
        assertNotNull(handle)
        assertFalse(called, "providers must be lazy until invoked")
        assertEquals("resp", String(handle!!.responseBytes()!!))
        assertTrue(called)
    }

    @Test
    fun `evicts least-recently-used beyond capacity`() {
        val reg = MessageRegistry(maxEntries = 2)
        reg.put(handle("a"))
        reg.put(handle("b"))
        reg.get("a") // touch a so b is now LRU
        reg.put(handle("c")) // should evict b
        assertNotNull(reg.get("a"))
        assertNotNull(reg.get("c"))
        assertNull(reg.get("b"))
        assertEquals(2, reg.size())
    }

    @Test
    fun `id helpers are stable and formatted`() {
        assertEquals("ph:3", MessageRegistry.proxyHistoryId(3))
        assertEquals("iss:9", MessageRegistry.issueId(9))
        assertEquals(MessageRegistry.siteMapId("https://x/y"), MessageRegistry.siteMapId("https://x/y"))
        assertTrue(MessageRegistry.siteMapId("https://x/y").startsWith("sm:"))
    }

    private fun handle(id: String) = MessageRegistry.Handle(id, null, { null }, { null })
}
