package com.revoltsecurities.burpmcp.output

import java.util.Collections

/**
 * Maps stable ids to the bytes behind an HTTP message, so list rows can carry a tiny `id` and the agent
 * fetches request/response bytes on demand (byte-range sliced) instead of lists ever embedding bodies.
 *
 * Ids are source-derived and stable (`ph:<index>`, `sm:<sha1(url)>`, `iss:<index>`), so even after a
 * registry eviction the tool layer can re-resolve from Montoya and re-register the same id. The registry is
 * therefore a bounded LRU fast-path cache, not the source of truth. Byte providers are lazy — nothing is
 * materialised until the agent actually asks for a slice.
 */
class MessageRegistry(private val maxEntries: Int = DEFAULT_MAX_ENTRIES) {

    data class Handle(
        val id: String,
        val mimeType: String?,
        val requestBytes: () -> ByteArray?,
        val responseBytes: () -> ByteArray?,
    )

    private val lru: MutableMap<String, Handle> = Collections.synchronizedMap(
        object : LinkedHashMap<String, Handle>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: Map.Entry<String, Handle>): Boolean = size > maxEntries
        },
    )

    fun put(handle: Handle): String {
        lru[handle.id] = handle
        return handle.id
    }

    fun get(id: String): Handle? = lru[id]

    fun size(): Int = lru.size

    companion object {
        const val DEFAULT_MAX_ENTRIES = 2_048

        /** Stable id for a proxy-history item (assignment index). */
        fun proxyHistoryId(index: Int): String = "ph:$index"

        /** Stable id for a site-map entry. Includes the entry index because many entries can share a URL. */
        fun siteMapId(url: String, index: Int): String = "sm:${shortHash(url)}:$index"

        /** Stable id for a scanner issue (index). */
        fun issueId(index: Int): String = "iss:$index"

        private fun shortHash(value: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-1").digest(value.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }.take(16)
        }
    }
}
