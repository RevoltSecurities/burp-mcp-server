package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.ByteBudget
import com.revoltsecurities.burpmcp.output.CursorCodec
import com.revoltsecurities.burpmcp.output.PageEnvelope
import com.revoltsecurities.burpmcp.output.TruncationMarker

/**
 * Pure keyset paging: sort the (already-filtered) items by a lexicographically-sortable key, resume strictly
 * after the cursor's key, take up to [limit], then trim to the byte budget. Produces a [PageEnvelope] with a
 * keyset `nextCursor` and a resumable truncation note. No Montoya, fully unit-testable.
 */
object Pager {

    /** Zero-pad an int so numeric keys sort correctly as strings (e.g. "9" must sort before "10"). */
    fun intKey(value: Int): String = value.toString().padStart(12, '0')

    fun <T, R> page(
        all: List<T>,
        keyOf: (T) -> String,
        ordering: String,
        cursor: String?,
        filterHash: String,
        limit: Int,
        maxBytes: Int,
        toRow: (T) -> R,
        measure: (R) -> Int,
    ): PageEnvelope<R> {
        val sorted = all.sortedBy(keyOf)

        val afterCursor = if (cursor.isNullOrEmpty()) {
            sorted
        } else {
            val pos = CursorCodec.decode(cursor, filterHash) // throws InvalidCursorException on mismatch
            sorted.filter { keyOf(it) > pos.lastKey }
        }

        val window = afterCursor.take(limit)
        val moreBeyondLimit = afterCursor.size > window.size

        // Map to rows, then enforce the whole-envelope byte budget.
        val rows = window.map(toRow)
        val fit = ByteBudget.fit(rows, maxBytes, measure)
        val keptCount = fit.kept.size
        val keptSource = window.take(keptCount)

        val hasMore = moreBeyondLimit || fit.truncated
        val nextCursor = if (hasMore && keptSource.isNotEmpty()) {
            CursorCodec.encode(keyOf(keptSource.last()), filterHash, ordering)
        } else {
            null
        }

        val truncation = if (fit.truncated) {
            TruncationMarker(
                reason = "Page shortened to fit the result-size budget; ${fit.droppedCount} row(s) deferred.",
                nextAction = "call the same tool again with cursor=<nextCursor> to continue",
                rowsOmitted = fit.droppedCount,
            )
        } else {
            null
        }

        return PageEnvelope(
            items = fit.kept,
            nextCursor = nextCursor,
            hasMore = hasMore,
            returned = fit.kept.size,
            totalCount = all.size,
            totalIsEstimate = false,
            truncation = truncation,
        )
    }
}
