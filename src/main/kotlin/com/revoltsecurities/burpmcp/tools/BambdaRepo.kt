package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

/** One `.bambda` file in the official PortSwigger/bambdas repo (listing row — no body). */
@Serializable
data class BambdaRepoEntry(val path: String, val name: String, val category: String)

/**
 * Read-only access to the official PortSwigger/bambdas GitHub repo. The implementation hits a HARD-CODED GitHub
 * host for that one repo and accepts a repo-relative path only — there is no arbitrary-URL fetch and thus no SSRF
 * surface. Scripts are LGPL-3.0 with per-file `@author`; callers must preserve those headers.
 */
interface BambdaRepo {
    /** All `.bambda` files in the repo (cached). */
    suspend fun listScripts(): List<BambdaRepoEntry>

    /** Raw text of one `.bambda` file by its repo-relative path (validated). */
    suspend fun fetch(path: String): String

    companion object {
        const val REPO = "PortSwigger/bambdas"
        const val BRANCH = "main"

        /** Validate a repo-relative path: `.bambda` only, no traversal/absolute/scheme/backslash. */
        fun safePath(raw: String): String {
            val p = raw.trim().trimStart('/')
            require(p.isNotEmpty()) { "Empty path" }
            require(p.endsWith(".bambda")) { "Only .bambda files can be fetched" }
            require(!p.contains("..") && !p.contains("://") && !p.contains('\\')) { "Invalid path '$raw'" }
            require(!p.startsWith("/")) { "Path must be repo-relative" }
            // Reject percent-encoded traversal/separators so an encoded `..%2f` can't slip past the checks
            // above before the path is appended to the raw.githubusercontent.com URL (defense-in-depth).
            val lower = p.lowercase()
            require(!lower.contains("%2e") && !lower.contains("%2f") && !lower.contains("%5c")) { "Invalid path '$raw'" }
            return p
        }

        /** Top-level folder → category (e.g. "Filter/Proxy/HTTP/x.bambda" → "Filter"). */
        fun categoryOf(path: String): String = path.substringBefore('/', path)
    }
}
