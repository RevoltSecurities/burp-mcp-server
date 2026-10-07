package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionProfile

/**
 * Pure raw-HTTP request mutation for session injection. Applies a [SessionProfile] to a raw request:
 * adds/replaces headers (case-insensitive), merges cookies into the `Cookie` header, and ensures a `Host`
 * header is present (profile `hostOverride` wins; otherwise a `Host` is only ADDED when missing so crafted
 * smuggling/desync requests keep their own). Idempotent and Montoya-free → unit-tested.
 *
 * This is the single fix point for two reported defects: the "status 0 / length 0" symptom (a request sent
 * with no/mismatched Host gets no response) and the missing session-injection capability across the send tools.
 */
object SessionInjector {

    /**
     * @param raw the full raw HTTP request.
     * @param profile headers/cookies/hostOverride to apply.
     * @param targetHost the connection host; used to fill a missing `Host` header. Null = leave Host alone.
     */
    fun apply(raw: String, profile: SessionProfile, targetHost: String? = null): String {
        if (raw.isBlank()) return raw

        // Detect line terminator from the first break so we preserve the request's own style.
        val firstLf = raw.indexOf('\n')
        val eol = if (firstLf > 0 && raw[firstLf - 1] == '\r') "\r\n" else "\n"
        val sep = eol + eol

        val sepIdx = raw.indexOf(sep)
        val head = if (sepIdx >= 0) raw.substring(0, sepIdx) else raw
        val body = if (sepIdx >= 0) raw.substring(sepIdx + sep.length) else ""

        val headLines = head.split(eol)
        val requestLine = headLines.firstOrNull() ?: return raw
        val headers = headLines.drop(1).filter { it.isNotEmpty() }.toMutableList()

        // Byte-exact fast path: nothing to inject and a Host is present (or none to add). Preserves crafted
        // request-smuggling/desync payloads — the race tools must not have their raw requests normalized.
        val hostPresent = headers.any { it.substringBefore(':').trim().equals("Host", ignoreCase = true) }
        if (profile.isEmpty && (targetHost.isNullOrBlank() || hostPresent)) return raw

        fun indexOfHeader(name: String): Int =
            headers.indexOfFirst { it.substringBefore(':').trim().equals(name, ignoreCase = true) }

        fun setHeader(name: String, value: String) {
            val line = "$name: $value"
            val idx = indexOfHeader(name)
            if (idx >= 0) headers[idx] = line else headers.add(line)
        }

        // 1. Host — forced by hostOverride, else filled only when absent (keeps crafted requests intact).
        val override = profile.hostOverride?.takeIf { it.isNotBlank() }
        if (override != null) {
            setHeader("Host", override)
        } else if (indexOfHeader("Host") < 0 && !targetHost.isNullOrBlank()) {
            setHeader("Host", targetHost)
        }

        // 2. Arbitrary headers (Authorization, X-*, etc.) — add or replace.
        profile.headers.forEach { (n, v) -> if (n.isNotBlank()) setHeader(n.trim(), v) }

        // 3. Cookies — collapse ALL Cookie headers (HTTP/2 may split them) into one, overriding same-named.
        if (profile.cookies.isNotEmpty()) {
            val merged = LinkedHashMap<String, String>()
            val cookieIdxs = headers.indices.filter { headers[it].substringBefore(':').trim().equals("Cookie", ignoreCase = true) }
            cookieIdxs.forEach { idx ->
                headers[idx].substringAfter(':').split(';').forEach { part ->
                    val p = part.trim()
                    if (p.isNotEmpty()) merged[p.substringBefore('=').trim()] = p.substringAfter('=', "")
                }
            }
            cookieIdxs.sortedDescending().forEach { headers.removeAt(it) } // drop the originals
            profile.cookies.forEach { (n, v) -> if (n.isNotBlank()) merged[n.trim()] = v }
            headers.add("Cookie: " + merged.entries.joinToString("; ") { "${it.key}=${it.value}" })
        }

        return (listOf(requestLine) + headers).joinToString(eol) + sep + body
    }
}
