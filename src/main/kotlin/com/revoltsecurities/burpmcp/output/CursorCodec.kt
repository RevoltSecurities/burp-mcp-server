package com.revoltsecurities.burpmcp.output

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.util.Base64

/**
 * Opaque, stateless **keyset** cursors (base64url of a tiny JSON record). The cursor encodes the last
 * emitted sort key, a hash of the active filter set, and the ordering id — not an offset. On decode we
 * verify the filter hash matches the current request so a client that changes filters mid-page is
 * rejected (JSON-RPC -32602 territory) instead of silently restarting at page 1.
 *
 * Keyset cursors survive new items arriving between pages and are O(1) to resume, unlike drop/take.
 */
object CursorCodec {

    @Serializable
    private data class CursorRecord(val k: String, val f: String, val o: String)

    /** A validated cursor position: resume strictly AFTER [lastKey] under ordering [ordering]. */
    data class Position(val lastKey: String, val ordering: String)

    class InvalidCursorException(message: String) : Exception(message)

    private val json = Json { encodeDefaults = true }
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(lastKey: String, filterHash: String, ordering: String): String {
        val bytes = json.encodeToString(CursorRecord.serializer(), CursorRecord(lastKey, filterHash, ordering))
            .toByteArray(Charsets.UTF_8)
        return encoder.encodeToString(bytes)
    }

    /**
     * Decode and validate a cursor against the current [expectedFilterHash].
     * @throws InvalidCursorException if the cursor is unparseable or was issued for a different filter set.
     */
    fun decode(cursor: String, expectedFilterHash: String): Position {
        val record = runCatching {
            json.decodeFromString(CursorRecord.serializer(), String(decoder.decode(cursor), Charsets.UTF_8))
        }.getOrElse {
            throw InvalidCursorException("Cursor is malformed; restart the listing without a cursor.")
        }
        if (record.f != expectedFilterHash) {
            throw InvalidCursorException(
                "Cursor was issued for a different filter set; restart the listing without a cursor after changing filters.",
            )
        }
        return Position(lastKey = record.k, ordering = record.o)
    }

    /** Stable hash of the active filter set, so cursors are bound to the filters that produced them. */
    fun filterHash(filters: Map<String, String?>): String {
        val canonical = filters.entries
            .filter { it.value != null }
            .sortedBy { it.key }
            .joinToString("&") { "${it.key}=${it.value}" }
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest).take(16)
    }
}
