package com.revoltsecurities.burpmcp.output

/**
 * Byte-range slicing for large HTTP bodies. Returns a bounded window plus a resumable [TruncationMarker]
 * telling the agent the exact next call to continue. Binary content is never dumped into the LLM context —
 * it is reported as metadata only (encoding = "omitted").
 */
object BodySlicer {

    enum class Encoding { UTF8, OMITTED }

    data class Slice(
        val encoding: Encoding,
        val totalBytes: Int,
        val offset: Int,
        val length: Int,
        val content: String,
        val mimeType: String?,
        val truncation: TruncationMarker?,
    )

    /**
     * @param bytes full body bytes
     * @param offset requested start (clamped to [0, totalBytes])
     * @param length requested length (clamped to [0, maxLength])
     * @param mimeType content type; binary types yield an omitted body
     * @param maxLength hard cap on how many bytes this call may return
     * @param continuationHint builds the nextAction string for a given next offset (e.g. the get_http_message call)
     */
    fun slice(
        bytes: ByteArray,
        offset: Int,
        length: Int,
        mimeType: String?,
        maxLength: Int,
        continuationHint: (nextOffset: Int) -> String,
    ): Slice {
        val total = bytes.size

        if (isBinary(mimeType)) {
            return Slice(
                encoding = Encoding.OMITTED,
                totalBytes = total,
                offset = 0,
                length = 0,
                content = "",
                mimeType = mimeType,
                truncation = if (total > 0) {
                    TruncationMarker(
                        reason = "Binary content ($mimeType) not inlined; fetch as a resource instead.",
                        nextAction = continuationHint(0),
                        bytesOmitted = total.toLong(),
                    )
                } else {
                    null
                },
            )
        }

        // Snap the START forward to a char boundary too, not just the end. A caller-supplied offset (not one
        // of our snapped nextAction offsets) can land mid-multibyte-char; beginning on a continuation byte
        // would decode those orphaned bytes to U+FFFD. The partial char's leading bytes belong to the prior
        // char, which a correctly-resumed earlier slice already emitted, so skipping them loses no data.
        val start = snapStartToCharBoundary(bytes, offset.coerceIn(0, total), total)
        val want = length.coerceIn(0, maxLength)
        val end = snapToCharBoundary(bytes, start, (start + want).coerceAtMost(total), total)
        val windowBytes = if (start >= end) ByteArray(0) else bytes.copyOfRange(start, end)
        val content = String(windowBytes, Charsets.UTF_8)
        val remaining = total - end

        val truncation = if (remaining > 0) {
            TruncationMarker(
                reason = "Body truncated: $remaining of $total bytes not shown.",
                nextAction = continuationHint(end),
                bytesOmitted = remaining.toLong(),
            )
        } else {
            null
        }

        return Slice(
            encoding = Encoding.UTF8,
            totalBytes = total,
            offset = start,
            length = windowBytes.size,
            content = content,
            mimeType = mimeType,
            truncation = truncation,
        )
    }

    /**
     * Snap the window end to a UTF-8 character boundary so a multibyte char is never split across slices
     * (which would decode to U+FFFD on both sides). If the whole body is consumed, no snapping is needed. If a
     * single char is larger than the requested window, extend to include it so paging always makes progress.
     */
    private fun snapToCharBoundary(bytes: ByteArray, start: Int, desiredEnd: Int, total: Int): Int {
        if (desiredEnd >= total) return desiredEnd // reaching the end: nothing to split
        var e = desiredEnd
        while (e > start && isContinuationByte(bytes[e])) e-- // back up to a boundary (lead byte / ASCII)
        if (e > start) return e
        // the first char alone exceeds the window — include the whole char to guarantee forward progress
        var f = start + 1
        while (f < total && isContinuationByte(bytes[f])) f++
        return f
    }

    /**
     * Snap a start offset forward to the next UTF-8 lead/ASCII byte, so a slice never begins in the middle of
     * a multibyte character. Advances past any continuation bytes at [start].
     */
    private fun snapStartToCharBoundary(bytes: ByteArray, start: Int, total: Int): Int {
        var s = start
        while (s < total && isContinuationByte(bytes[s])) s++
        return s
    }

    private fun isContinuationByte(b: Byte): Boolean = (b.toInt() and 0xC0) == 0x80

    /** Content types we never inline into text output. */
    fun isBinary(mimeType: String?): Boolean {
        if (mimeType == null) return false
        val m = mimeType.substringBefore(';').trim().lowercase()
        if (m.isEmpty()) return false
        if (m.startsWith("text/")) return false
        if (TEXTUAL_EXACT.contains(m)) return false
        if (m.endsWith("+json") || m.endsWith("+xml")) return false
        return m.startsWith("image/") ||
            m.startsWith("audio/") ||
            m.startsWith("video/") ||
            m.startsWith("font/") ||
            m == "application/octet-stream" ||
            m == "application/pdf" ||
            m == "application/zip" ||
            m == "application/gzip" ||
            m.startsWith("application/x-protobuf") ||
            m.startsWith("application/wasm")
    }

    private val TEXTUAL_EXACT = setOf(
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-www-form-urlencoded",
        "application/graphql",
        "application/ld+json",
    )
}
