package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionProfile

/**
 * Parses session-related tool arguments into a [SessionProfile]. Keeps the "Name: value" / "name=value"
 * wire shapes in one place so every send tool and `session_set` interpret them identically.
 */
object SessionArgs {

    /**
     * A per-call override from a send tool: a single `cookie` header value ("a=1; b=2") and/or `headers`
     * lines ("Name: value"). No host override at call scope.
     */
    fun perCallOverride(args: Args): SessionProfile {
        val cookies = parseCookieHeader(args.str("cookie"))
        val headers = parseHeaderLines(args.strList("headers"))
        return SessionProfile(cookies = cookies, headers = headers, hostOverride = null)
    }

    /** Parse comma/space-separated HTTP statuses (e.g. "401, 403"); empty → default [401,403]. Shared by tool + UI. */
    fun parseStatuses(s: String?): List<Int> {
        if (s.isNullOrBlank()) return listOf(401, 403)
        return s.split(',', ' ').mapNotNull { it.trim().toIntOrNull() }.ifEmpty { listOf(401, 403) }
    }

    /** `session_set`: `cookies` ["name=value"], `headers` ["Name: value"], optional `hostOverride`. */
    fun fromSetArgs(args: Args): SessionProfile = SessionProfile(
        cookies = parseKvPairs(args.strList("cookies")),
        headers = parseHeaderLines(args.strList("headers")),
        hostOverride = args.str("hostOverride"),
    )

    /** "Name: value" lines → map (later duplicates win). Lines without a colon are ignored. */
    private fun parseHeaderLines(lines: List<String>): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (line in lines) {
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            val name = line.substring(0, idx).trim()
            if (name.isNotEmpty()) out[name] = line.substring(idx + 1).trim()
        }
        return out
    }

    /** "name=value" entries → map. */
    private fun parseKvPairs(entries: List<String>): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (entry in entries) {
            val e = entry.trim()
            if (e.isEmpty() || !e.contains('=')) continue
            val name = e.substringBefore('=').trim()
            if (name.isNotEmpty()) out[name] = e.substringAfter('=', "")
        }
        return out
    }

    /** A Cookie header value "a=1; b=2" → map. */
    private fun parseCookieHeader(value: String?): Map<String, String> {
        if (value.isNullOrBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        value.split(';').forEach { part ->
            val p = part.trim()
            if (p.isNotEmpty() && p.contains('=')) out[p.substringBefore('=').trim()] = p.substringAfter('=', "")
        }
        return out
    }
}
