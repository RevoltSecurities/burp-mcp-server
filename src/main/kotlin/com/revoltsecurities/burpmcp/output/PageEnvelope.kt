package com.revoltsecurities.burpmcp.output

import kotlinx.serialization.Serializable

/**
 * Resumable truncation marker. Every elision — a dropped page tail or a sliced body — says what was
 * dropped and the exact next call to continue. No dead-end "[SNIP]" markers anywhere.
 */
@Serializable
data class TruncationMarker(
    val reason: String,
    val nextAction: String,
    val bytesOmitted: Long? = null,
    val rowsOmitted: Int? = null,
)

/**
 * Standard page envelope for every list tool. Carries typed [items], a keyset [nextCursor] (null = end),
 * counts, and an optional [truncation] note when the page was shortened to fit the byte budget.
 */
@Serializable
data class PageEnvelope<T>(
    val items: List<T>,
    val nextCursor: String? = null,
    val hasMore: Boolean = false,
    val returned: Int = items.size,
    val totalCount: Int? = null,
    val totalIsEstimate: Boolean = false,
    val truncation: TruncationMarker? = null,
)
