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

        val start = offset.coerceIn(0, total)
        val want = length.coerceIn(0, maxLength)
        val end = (start + want).coerceAtMost(total)
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
