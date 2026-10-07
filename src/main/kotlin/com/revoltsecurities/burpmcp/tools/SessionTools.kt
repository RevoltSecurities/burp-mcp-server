package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionLogin
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

@Serializable
data class SessionLoginView(
    val enabled: Boolean,
    val request: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val extractRegex: String,
    val location: String,
    val name: String,
    val template: String,
    val triggerStatuses: List<Int>,
    val redacted: Boolean,
    val note: String,
)

@Serializable
data class SessionLoginNowResult(val refresh: RefreshOutcome, val profile: SessionProfileView)

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
    private val loginProvider: () -> SessionLogin = { SessionLogin() },
    private val updateLogin: (SessionLogin) -> Unit = {},
    private val refreshService: SessionRefreshService? = null,
) {
    fun build(): List<ToolSpec> = listOf(
        sessionSet(), sessionGet(), sessionClear(),
        sessionLoginSet(), sessionLoginGet(), sessionLoginClear(), sessionLoginNow(),
    )

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

    // ---- auto-login / session refresh ----

    private fun sessionLoginSet(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("request", "The raw HTTP login request to replay when the session expires. " + Descriptions.RAW_REQUEST, required = true)
            string("host", Descriptions.TARGET_HOST, required = true)
            integer("port", Descriptions.TARGET_PORT)
            boolean("secure", Descriptions.TARGET_SECURE, default = true)
            string("extractRegex", "Regex run over the login RESPONSE (headers+body); capture group 1 is the token (e.g. \"\\\"access_token\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"\"). If there is no group, the whole match is used.", required = true)
            string("location", "Where to put the fresh token on subsequent requests.", enum = listOf("header", "cookie"), default = "header")
            string("name", "Header name (e.g. Authorization) or cookie name to set the token on.", default = "Authorization")
            string("template", "How to format the header/cookie value; {token} is substituted. E.g. \"Bearer {token}\". Default \"{token}\".", default = "{token}")
            string("triggerStatuses", "Comma-separated response statuses that auto-trigger a refresh for in-scope scanner traffic. Default \"401,403\".", default = "401,403")
            boolean("enabled", "Enable auto-refresh.", default = true)
        }
        return ToolSpec("session_login_set", "Set session login", DESC_LOGIN_SET, "Session", schema, mutating = true) { args ->
            val secure = args.boolOr("secure", true)
            val login = SessionLogin(
                enabled = args.boolOr("enabled", true),
                request = args.require("request"),
                host = args.require("host"),
                port = args.int("port") ?: 0,
                secure = secure,
                extractRegex = args.require("extractRegex"),
                location = args.strOr("location", "header"),
                name = args.strOr("name", "Authorization"),
                template = args.strOr("template", "{token}"),
                triggerStatuses = SessionArgs.parseStatuses(args.str("triggerStatuses")),
            )
            runCatching { Regex(login.extractRegex) }.onFailure {
                return@ToolSpec Results.error("Invalid extractRegex (does not compile): ${it.message}")
            }
            updateLogin(login)
            Results.structured(SessionLoginView.serializer(), loginView(login, "Session login saved. It will refresh the token on ${login.triggerStatuses} for in-scope scans; call session_login_now to force it."))
        }
    }

    private fun sessionLoginGet(): ToolSpec =
        ToolSpec("session_login_get", "Get session login", "Show the auto-login config. The raw login request is redacted unless the unsafe master switch is on.", "Session", SchemaBuilder.empty()) {
            val l = loginProvider()
            val note = if (!l.isConfigured) "No session login configured (or disabled). Use session_login_set." else "Auto-login is configured."
            Results.structured(SessionLoginView.serializer(), loginView(l, note))
        }

    private fun sessionLoginClear(): ToolSpec =
        ToolSpec("session_login_clear", "Clear session login", "Remove the auto-login config (no automatic token refresh afterwards).", "Session", SchemaBuilder.empty(), mutating = true) {
            updateLogin(SessionLogin())
            Results.structured(SessionLoginView.serializer(), loginView(SessionLogin(), "Session login cleared."))
        }

    private fun sessionLoginNow(): ToolSpec =
        ToolSpec("session_login_now", "Refresh session now", "Force an immediate login replay: fetch a fresh token and rotate it into the session profile. Use when a send/intruder/race request returns 401/403.", "Session", SchemaBuilder.empty(), mutating = true) {
            val svc = refreshService
                ?: return@ToolSpec Results.error("Session refresh is unavailable in this build.")
            val outcome = svc.refresh(force = true)
            val res = SessionLoginNowResult(outcome, view(profileProvider(), if (outcome.ok) "Profile updated." else "Profile unchanged."))
            if (outcome.ok) Results.structured(SessionLoginNowResult.serializer(), res)
            else Results.structuredError(SessionLoginNowResult.serializer(), res)
        }

    private fun loginView(l: SessionLogin, note: String): SessionLoginView {
        val reveal = unsafeEnabled()
        val req = when {
            l.request.isEmpty() -> ""
            reveal -> l.request
            else -> "[REDACTED ${l.request.length} chars]"
        }
        return SessionLoginView(
            enabled = l.enabled, request = req, host = l.host, port = l.port, secure = l.secure,
            extractRegex = l.extractRegex, location = l.location, name = l.name, template = l.template,
            triggerStatuses = l.triggerStatuses, redacted = !reveal, note = note,
        )
    }

    private fun view(p: SessionProfile, note: String): SessionProfileView {
        val reveal = unsafeEnabled()
        fun redact(m: Map<String, String>): Map<String, String> =
            if (reveal) m else m.mapValues { "[REDACTED]" }
        return SessionProfileView(redact(p.cookies), redact(p.headers), p.hostOverride, redacted = !reveal, note = note)
    }

    companion object {
        private const val DESC_LOGIN_SET =
            "Configure NATIVE session auto-refresh (no Burp macro needed): store a login request + a regex that " +
                "pulls the token from the login response. When an in-scope scan sees a trigger status (default " +
                "401/403) the extension replays the login, extracts a fresh token, and rotates it into the session " +
                "profile; call session_login_now to force it for the send/intruder/race tools. The login request is " +
                "sent with its own credentials (not the stale token) and is encrypted at rest."
        private const val DESC_SET =
            "Store a reusable auth/session profile (cookies, headers, optional Host override) that is AUTO-APPLIED " +
                "to every http_send/http_send_analyze/http_send_compare/intruder_attack/race_* request and the audit " +
                "seed, AND to every IN-SCOPE request Burp's scanner/crawler generates (no session-handling rule " +
                "needed; the profile is never sent to out-of-scope hosts). Set it once to keep long, compaction-prone " +
                "runs authenticated. Only token REFRESH (re-login on 401) still needs a Burp login macro + rule in the UI."
    }
}
