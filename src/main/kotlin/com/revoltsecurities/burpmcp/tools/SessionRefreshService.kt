package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionLogin
import com.revoltsecurities.burpmcp.config.SessionProfile
import kotlinx.serialization.Serializable
import java.util.concurrent.atomic.AtomicBoolean

/** Result of a refresh attempt. Never carries the token itself — only its length. */
@Serializable
data class RefreshOutcome(
    val ok: Boolean,
    val status: String, // refreshed | skipped | failed | not_configured
    val loginStatus: Int? = null,
    val tokenLength: Int? = null,
    val target: String? = null,
    val note: String,
)

/**
 * Replays the configured login request, extracts a fresh token, and rotates it into the stored session profile.
 * Single-flight + time-debounced so a burst of 401s (e.g. many scanner requests at once) triggers at most one
 * login. The `send` seam is [BurpActions.sendRequest], which applies only Host-ensure (NOT the session profile),
 * so the login goes out with its own credentials rather than the stale token. Logic is testable via fakes.
 */
class SessionRefreshService(
    private val send: (raw: String, host: String, port: Int, secure: Boolean) -> SentExchange,
    private val loginProvider: () -> SessionLogin,
    private val currentProfile: () -> SessionProfile,
    private val updateProfile: (SessionProfile) -> Unit,
    /** True if a login to (host,port,secure) is allowed by scope confinement. Default: always allowed. */
    private val scopeAllows: (host: String, port: Int, secure: Boolean) -> Boolean = { _, _, _ -> true },
    private val minIntervalMs: Long = 5_000,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private val inFlight = AtomicBoolean(false)

    @Volatile
    private var lastRefreshAt = 0L

    /** Cheap, non-blocking check for callers on a hot thread: would [status] trigger a refresh right now? */
    fun wantsRefresh(status: Int): Boolean =
        loginProvider().let { it.isConfigured && SessionRefresher.shouldTrigger(status, it.triggerStatuses) }

    /** Refresh if [status] is a configured trigger (and login is configured). Debounced. */
    fun maybeRefreshOnStatus(status: Int): RefreshOutcome {
        if (!wantsRefresh(status)) return RefreshOutcome(false, "skipped", note = "Status $status is not a refresh trigger.")
        return refresh(force = false)
    }

    /** Perform (or skip) a refresh. [force] bypasses the debounce interval but not single-flight. */
    fun refresh(force: Boolean): RefreshOutcome {
        val login = loginProvider()
        if (!login.isConfigured) {
            return RefreshOutcome(false, "not_configured", note = "Session login is not enabled/complete. Use session_login_set.")
        }
        val now = clock()
        if (!force && now - lastRefreshAt < minIntervalMs) {
            return RefreshOutcome(false, "skipped", note = "Debounced (refreshed < ${minIntervalMs}ms ago).")
        }
        if (!inFlight.compareAndSet(false, true)) {
            return RefreshOutcome(false, "skipped", note = "A refresh is already in progress.")
        }
        try {
            // Debounce on EVERY attempt (incl. failures) so a bad login can't re-fire on each triggering response.
            lastRefreshAt = now
            val port = if (login.port > 0) login.port else if (login.secure) 443 else 80
            if (!scopeAllows(login.host, port, login.secure)) {
                return RefreshOutcome(false, "failed", note = "Login host '${login.host}' is out of scope and scope-confinement is enabled. Add it to scope or disable confinement.")
            }
            val ex = send(login.request, login.host, port, login.secure)
            if (ex.error != null) return RefreshOutcome(false, "failed", ex.statusCode, note = "Login request failed: ${ex.error}")
            val respText = (ex.responseBytes?.toString(Charsets.UTF_8) ?: "").take(MAX_SCAN_CHARS)
            if (respText.isEmpty()) return RefreshOutcome(false, "failed", ex.statusCode, note = "Login returned no response body.")
            val token = SessionRefresher.extractToken(respText, login.extractRegex)
                ?: return RefreshOutcome(false, "failed", ex.statusCode, note = "extractRegex matched no token in the login response (status ${ex.statusCode}).")
            updateProfile(currentProfile().mergedWith(SessionRefresher.profileDelta(token, login)))
            return RefreshOutcome(
                true, "refreshed", ex.statusCode, token.length,
                target = "${login.location}:${login.name}",
                note = "Rotated a fresh token into the session profile (${login.location} '${login.name}').",
            )
        } finally {
            inFlight.set(false)
        }
    }

    private companion object {
        // Bound the text an (agent-supplied) extractRegex scans, to limit catastrophic-backtracking surface.
        const val MAX_SCAN_CHARS = 2_000_000
    }
}
