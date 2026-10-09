package com.revoltsecurities.burpmcp.output

import com.revoltsecurities.burpmcp.tools.Pager
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** Tests for the context-management correctness fixes (byte budget overhead, slice start snapping, ordering). */
class ByteBudgetOverheadTest {

    @Test
    fun `perItemOverhead charges separators between rows`() {
        // 4 items of 2 bytes = 8 bytes of content; with a 1-byte separator each (after the first) that is
        // 8 + 3 = 11. A budget of 10 must therefore drop the last row, unlike the overhead-free sum of 8.
        val items = listOf("aa", "bb", "cc", "dd")
        val withOverhead = ByteBudget.fit(items, maxBytes = 10, perItemOverhead = 1) { it.length }
        assertTrue(withOverhead.truncated)
        assertEquals(3, withOverhead.kept.size)

        val withoutOverhead = ByteBudget.fit(items, maxBytes = 10) { it.length }
        assertFalse(withoutOverhead.truncated)
        assertEquals(4, withoutOverhead.kept.size)
    }
}

class BodySlicerStartSnapTest {

    private val hint: (Int) -> String = { next -> "offset=$next" }

    @Test
    fun `start offset landing mid-multibyte-char snaps forward and never emits U+FFFD`() {
        // "é" is 2 bytes (0xC3 0xA9). Starting at offset 1 lands on the continuation byte 0xA9.
        val body = ("é".repeat(3)).toByteArray(Charsets.UTF_8) // 6 bytes
        val slice = BodySlicer.slice(body, offset = 1, length = 100, mimeType = "text/plain", maxLength = 100, continuationHint = hint)
        assertFalse(slice.content.contains('�'), "must not begin inside a char")
        // offset 1 skips forward past the orphaned continuation byte to the next char boundary (offset 2).
        assertEquals(2, slice.offset)
        assertEquals("éé", slice.content)
    }
}

class CursorOrderingGuardTest {

    @Test
    fun `cursor is rejected when the ordering changes but filters do not`() {
        val fh = CursorCodec.filterHash(mapOf("host" to "x"))
        val cursor = CursorCodec.encode(lastKey = "5", filterHash = fh, ordering = "index")
        // Same filter hash, different ordering → must be rejected rather than silently resuming under a new sort.
        assertThrows(CursorCodec.InvalidCursorException::class.java) {
            CursorCodec.decode(cursor, fh, expectedOrdering = "url")
        }
        // Matching ordering still decodes.
        val pos = CursorCodec.decode(cursor, fh, expectedOrdering = "index")
        assertEquals("5", pos.lastKey)
    }

    @Test
    fun `pager rejects a cursor whose ordering differs from the request`() {
        data class Item(val n: Int)
        val all = (1..5).map { Item(it) }
        val p1 = Pager.page(
            all = all, keyOf = { Pager.intKey(it.n) }, ordering = "n",
            cursor = null, filterHash = "fh", limit = 2, maxBytes = 10_000,
            toRow = { it.n }, measure = { 4 },
        )
        // Re-use p1's cursor under a different ordering id → InvalidCursorException.
        assertThrows(CursorCodec.InvalidCursorException::class.java) {
            Pager.page(
                all = all, keyOf = { Pager.intKey(it.n) }, ordering = "different",
                cursor = p1.nextCursor, filterHash = "fh", limit = 2, maxBytes = 10_000,
                toRow = { it.n }, measure = { 4 },
            )
        }
    }
}
