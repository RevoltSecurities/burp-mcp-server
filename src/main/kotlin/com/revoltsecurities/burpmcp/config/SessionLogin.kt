package com.revoltsecurities.burpmcp.config

import kotlinx.serialization.Serializable

/**
 * Optional auto-login config that keeps a rotating session alive. When a trigger status (e.g. 401/403) is seen on
 * in-scope scanner traffic — or `session_login_now` is called — the extension replays [request], extracts a fresh
 * token with [extractRegex], and rotates it into the stored [SessionProfile]. This is the native alternative to a
 * Burp login macro + session-handling rule (which Montoya cannot create programmatically).
 *
 * [request] holds credentials, so it is encrypted at rest (see `SettingsStore`) and redacted by `session_login_get`.
 *
 * - [extractRegex]: matched over the login RESPONSE (headers+body); group 1 is the token (else the whole match).
 * - [location]/[name]/[template]: where the token goes — a header `name: <template with {token}>` (default
 *   `Authorization: {token}`) or a cookie `name=<token>`.
 * - [triggerStatuses]: response statuses that trigger an auto-refresh for in-scope scanner traffic.
 */
@Serializable
data class SessionLogin(
    val enabled: Boolean = false,
    val request: String = "",
    val host: String = "",
    val port: Int = 0,
    val secure: Boolean = true,
    val extractRegex: String = "",
    val location: String = "header",
    val name: String = "Authorization",
    val template: String = "{token}",
    val triggerStatuses: List<Int> = listOf(401, 403),
) {
    /** True when enough is set to actually perform a refresh. */
    val isConfigured: Boolean
        get() = enabled && request.isNotBlank() && host.isNotBlank() && extractRegex.isNotBlank() && name.isNotBlank()
}
