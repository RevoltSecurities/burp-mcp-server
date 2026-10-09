package com.revoltsecurities.burpmcp.output

/**
 * Whole-envelope byte budgeting. Rather than capping each item independently (which lets `limit * perItem`
 * blow the context), we add items until the next one would exceed [maxBytes], then stop and report how many
 * were dropped so the caller can set a cursor + truncation marker. Never mid-serialize truncates a row.
 */
object ByteBudget {

    data class Fit<T>(
        val kept: List<T>,
        val droppedCount: Int,
        val usedBytes: Int,
    ) {
        val truncated: Boolean get() = droppedCount > 0
    }

    /**
     * Keep a prefix of [items] whose measured sizes sum within [maxBytes]. Always keeps at least one item
     * (even if it alone exceeds the budget) so progress is guaranteed; that single oversized item should be
     * sliced separately by the caller.
     *
     * [perItemOverhead] is added to every item after the first — use it to account for the separators a
     * serializer inserts between elements (e.g. the `,` between JSON array rows), so the measured budget
     * tracks the real wire size rather than the bare sum of row bodies.
     */
    fun <T> fit(items: List<T>, maxBytes: Int, perItemOverhead: Int = 0, measure: (T) -> Int): Fit<T> {
        if (items.isEmpty()) return Fit(emptyList(), 0, 0)
        val kept = ArrayList<T>(items.size)
        var used = 0
        for ((index, item) in items.withIndex()) {
            if (index == 0) {
                kept.add(item); used += measure(item); continue
            }
            val size = measure(item) + perItemOverhead
            if (used + size > maxBytes) break
            kept.add(item); used += size
        }
        return Fit(kept, items.size - kept.size, used)
    }

    /** Cheap byte estimate for a string result (UTF-8). */
    fun utf8Size(s: String): Int = s.toByteArray(Charsets.UTF_8).size
}
