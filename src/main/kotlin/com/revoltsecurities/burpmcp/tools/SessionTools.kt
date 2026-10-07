package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionProfile
import kotlinx.serialization.Serializable

@Serializable
data class SessionProfileView(
    val cookies: Map<String, String>,
    val headers: Map<String, String>,
    val hostOverride: String? = null,
    val redacted: Boolean,
    val note: String,
)

/**
 * Manage the reusable auth/session profile (cookies + headers + optional Host override) that every send-style
 * tool auto-applies and a registered Burp session-handling action injects into scanner traffic. Set it ONCE;
 * it persists (encrypted) across context compaction and Burp restarts, so long autonomous runs stay authed.
 *
 * Values are secrets (session tokens), so `session_get` redacts them unless the unsafe master switch is on —
 * same policy as `cookie_jar_get`.
 */
class SessionTools(
    private val profileProvider: () -> SessionProfile,
    private val updateProfile: (SessionProfile) -> Unit,
    private val unsafeEnabled: () -> Boolean = { false },
) {
    fun build(): List<ToolSpec> = listOf(sessionSet(), sessionGet(), sessionClear())

    private fun sessionSet(): ToolSpec {
        val schema = SchemaBuilder.build {
            stringArray("cookies", "Cookies to store, each \"name=value\" (e.g. [\"session=abc\", \"csrf=xyz\"]). Merged into requests' Cookie header.")
            stringArray("headers", "Headers to store, each \"Name: value\" (e.g. [\"Authorization: Bearer eyJ...\"]). Added/replacing same-named headers on every send.")
            string("hostOverride", "Optional Host header value to force on every request (e.g. for vhost routing). Omit to leave each request's Host alone.")
            boolean("replace", "true = replace the whole stored profile with these values; false (default) = merge over the existing profile.", default = false)
        }
        return ToolSpec("session_set", "Set session profile", DESC_SET, "Session", schema, mutating = true) { args ->
            val incoming = SessionArgs.fromSetArgs(args)
            val next = if (args.boolOr("replace", false)) incoming else profileProvider().mergedWith(incoming)
            updateProfile(next)
            Results.structured(SessionProfileView.serializer(), view(next, "Session profile saved and applied to all send tools + scanner traffic."))
        }
    }

    private fun sessionGet(): ToolSpec =
        ToolSpec("session_get", "Get session profile", "Show the stored session profile. Values are redacted unless the unsafe master switch is on.", "Session", SchemaBuilder.empty()) {
            val p = profileProvider()
            val note = if (p.isEmpty) "No session profile set. Use session_set to add cookies/headers for authenticated testing." else "Stored session profile."
            Results.structured(SessionProfileView.serializer(), view(p, note))
        }

    private fun sessionClear(): ToolSpec =
        ToolSpec("session_clear", "Clear session profile", "Remove the stored session profile (no cookies/headers/Host override are injected afterwards).", "Session", SchemaBuilder.empty(), mutating = true) {
            updateProfile(SessionProfile())
            Results.structured(SessionProfileView.serializer(), view(SessionProfile(), "Session profile cleared."))
        }

    private fun view(p: SessionProfile, note: String): SessionProfileView {
        val reveal = unsafeEnabled()
        fun redact(m: Map<String, String>): Map<String, String> =
            if (reveal) m else m.mapValues { "[REDACTED]" }
        return SessionProfileView(redact(p.cookies), redact(p.headers), p.hostOverride, redacted = !reveal, note = note)
    }

    companion object {
        private const val DESC_SET =
            "Store a reusable auth/session profile (cookies, headers, optional Host override) that is AUTO-APPLIED " +
                "to every http_send/http_send_analyze/http_send_compare/intruder_attack/race_* request and the audit " +
                "seed, and injected into scanner-generated requests via a Burp session-handling action. Set it once " +
                "to keep long, compaction-prone runs authenticated. For scanner-generated traffic you must also add, " +
                "one time in Burp, a Session handling rule whose action is \"Invoke a Burp extension\" → Revolt MCP."
    }
}
