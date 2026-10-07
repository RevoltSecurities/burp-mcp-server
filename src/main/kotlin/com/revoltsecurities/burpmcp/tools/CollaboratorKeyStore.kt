package com.revoltsecurities.burpmcp.tools

/**
 * Durable set of Collaborator client secret keys, backed by a simple string key/value store (in Burp,
 * `api.persistence().extensionData()`). Every generated payload's secret key is remembered here so an agent
 * can poll by interaction id or poll ALL clients later — even after the key dropped out of its context during
 * a long, compaction-prone run. Montoya-free (lambda-backed) → unit-tested.
 */
class CollaboratorKeyStore(
    private val get: (String) -> String?,
    private val set: (String, String) -> Unit,
) {
    /** Remember a secret key (idempotent). Oldest keys beyond [MAX_KEYS] are evicted to bound poll-all cost. */
    fun remember(secretKey: String) {
        if (secretKey.isBlank()) return
        val current = all().toMutableList()
        if (current.contains(secretKey)) return
        current.add(secretKey)
        while (current.size > MAX_KEYS) current.removeAt(0)
        set(KEY, current.joinToString("\n"))
    }

    /** All remembered secret keys, oldest first. */
    fun all(): List<String> =
        runCatching { get(KEY) }.getOrNull()?.split("\n")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()

    companion object {
        const val KEY = "revoltmcp.collab.secretkeys.v1"
        const val MAX_KEYS = 500
    }
}
