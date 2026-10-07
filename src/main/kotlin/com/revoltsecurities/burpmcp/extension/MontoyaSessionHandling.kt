package com.revoltsecurities.burpmcp.extension

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import com.revoltsecurities.burpmcp.config.SessionProfile
import com.revoltsecurities.burpmcp.tools.SessionInjector

/**
 * Registers ONE Burp session-handling action that injects the current [SessionProfile] (cookies/headers/Host)
 * into every request Burp routes through it — the only Montoya-reachable way to keep SCANNER-generated requests
 * authenticated (AuditConfiguration has no header/credential API). The user still adds, once in Burp, a
 * session-handling rule whose action is "Invoke a Burp extension" → this action, scoped to their target.
 *
 * It is a no-op when the profile is empty, and all Montoya calls are guarded so it degrades gracefully if an
 * older Burp lacks part of the session-handling API.
 */
class MontoyaSessionHandling(
    private val api: MontoyaApi,
    private val profile: () -> SessionProfile,
) {
    private var registration: Registration? = null

    fun start() {
        registration = runCatching {
            api.http().registerSessionHandlingAction(object : SessionHandlingAction {
                override fun name(): String = "Revolt MCP: inject session profile"

                override fun performAction(actionData: SessionHandlingActionData): ActionResult {
                    val p = profile()
                    val req = actionData.request()
                    if (p.isEmpty) return ActionResult.actionResult(req)
                    return runCatching {
                        val host = runCatching { req.httpService().host() }.getOrNull()
                        val raw = String(req.toByteArray().getBytes(), Charsets.ISO_8859_1)
                        val injected = SessionInjector.apply(raw, p, host)
                        ActionResult.actionResult(HttpRequest.httpRequest(req.httpService(), injected))
                    }.getOrDefault(ActionResult.actionResult(req))
                }
            })
        }.onFailure { api.logging().logToError("Session-handling action registration failed: ${it.message}") }
            .getOrNull()
    }

    fun stop() {
        runCatching { registration?.deregister() }
        registration = null
    }
}
