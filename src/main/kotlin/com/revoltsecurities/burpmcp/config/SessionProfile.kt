package com.revoltsecurities.burpmcp.config

import kotlinx.serialization.Serializable

/**
 * A reusable authentication/session profile applied to outbound requests from the send-style tools
 * (`http_send`, `http_send_analyze`/`http_send_compare`, `intruder_attack`, `race_*`) and the audit seed,
 * and — via a registered Burp session-handling action — to scanner-generated requests.
 *
 * It is held in [McpSettings] (sensitive values encrypted at rest, see `SettingsStore`) so it survives agent
 * context compaction and Burp restarts: set it ONCE with `session_set` and every send reuses it. A per-call
 * override can be merged on top for a single request.
 *
 * - [headers]: header name -> value; added, or replacing an existing same-named header (case-insensitive).
 * - [cookies]: cookie name -> value; merged into the request's `Cookie` header (same-named cookies overridden).
 * - [hostOverride]: when non-blank, the `Host` header value to force; otherwise a `Host` header is only added
 *   when the raw request lacks one.
 */
@Serializable
data class SessionProfile(
    val cookies: Map<String, String> = emptyMap(),
    val headers: Map<String, String> = emptyMap(),
    val hostOverride: String? = null,
) {
    val isEmpty: Boolean
        get() = cookies.isEmpty() && headers.isEmpty() && hostOverride.isNullOrBlank()

    /** Merge [other] on top of this profile; [other]'s values win on key collisions. */
    fun mergedWith(other: SessionProfile): SessionProfile {
        if (other.isEmpty) return this
        if (this.isEmpty) return other
        return SessionProfile(
            cookies = cookies + other.cookies,
            headers = headers + other.headers,
            hostOverride = other.hostOverride?.takeIf { it.isNotBlank() } ?: hostOverride,
        )
    }
}
