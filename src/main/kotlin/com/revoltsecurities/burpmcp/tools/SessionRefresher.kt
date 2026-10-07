package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionLogin
import com.revoltsecurities.burpmcp.config.SessionProfile

/**
 * Pure helpers for session auto-refresh: extract a fresh token from a login response and turn it into a
 * [SessionProfile] delta. Montoya-free → unit-tested. The actual send + state mutation lives in
 * [SessionRefreshService].
 */
object SessionRefresher {

    /** Token from the login response: regex group 1 if present, else the whole match. Null = no match. */
    fun extractToken(responseRaw: String, regex: String): String? {
        if (regex.isBlank()) return null
        val m = runCatching { Regex(regex).find(responseRaw) }.getOrNull() ?: return null
        return (m.groupValues.getOrNull(1)?.takeIf { it.isNotEmpty() } ?: m.value).takeIf { it.isNotEmpty() }
    }

    /** Build the profile delta that places [token] into the configured header or cookie. */
    fun profileDelta(token: String, login: SessionLogin): SessionProfile {
        val value = login.template.ifBlank { "{token}" }.replace("{token}", token)
        return if (login.location.equals("cookie", ignoreCase = true)) {
            SessionProfile(cookies = mapOf(login.name to value))
        } else {
            SessionProfile(headers = mapOf(login.name to value))
        }
    }

    fun shouldTrigger(status: Int, triggerStatuses: List<Int>): Boolean =
        if (triggerStatuses.isEmpty()) status == 401 || status == 403 else status in triggerStatuses
}
