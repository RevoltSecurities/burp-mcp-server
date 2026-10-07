package com.revoltsecurities.burpmcp.extension

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.core.ToolType
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.sessions.ActionResult
import burp.api.montoya.http.sessions.SessionHandlingAction
import burp.api.montoya.http.sessions.SessionHandlingActionData
import com.revoltsecurities.burpmcp.config.SessionProfile
import com.revoltsecurities.burpmcp.tools.SessionInjector
import com.revoltsecurities.burpmcp.tools.SessionRefreshService
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Applies the stored [SessionProfile] (cookies/headers/Host) to Burp-native traffic so SCANNER/crawler runs are
 * authenticated — the part the Montoya `AuditConfiguration` API can't do itself. Two mechanisms are registered:
 *
 * 1. **HTTP handler (automatic, no setup):** injects the profile into every request Burp's SCANNER sends that
 *    is IN SCOPE. Scope-gating is a safety requirement — it stops the auth token leaking to off-scope hosts the
 *    scanner may reach via redirects. So authenticated scans need only `session_set` + a defined target scope.
 * 2. **Session-handling action (opt-in):** for users who wire a Burp session-handling rule (e.g. alongside a
 *    Burp login macro for token refresh on 401). The rule invokes this action to inject the profile.
 *
 * No-op while the profile is empty; every Montoya call is guarded so it degrades gracefully.
 */
class MontoyaSessionHandling(
    private val api: MontoyaApi,
    private val profile: () -> SessionProfile,
    private val refreshService: SessionRefreshService? = null,
) {
    private val registrations = CopyOnWriteArrayList<Registration>()
    private val refreshPending = AtomicBoolean(false)

    fun start() {
        // 1. Automatic injection into in-scope scanner traffic.
        runCatching {
            registrations += api.http().registerHttpHandler(object : HttpHandler {
                override fun handleHttpRequestToBeSent(request: HttpRequestToBeSent): RequestToBeSentAction {
                    val p = profile()
                    if (p.isEmpty || !request.toolSource().isFromTool(ToolType.SCANNER)) {
                        return RequestToBeSentAction.continueWith(request)
                    }
                    return runCatching {
                        val url = request.url()
                        // Never attach credentials to out-of-scope requests (redirects off the target).
                        if (!api.scope().isInScope(url)) return@runCatching RequestToBeSentAction.continueWith(request)
                        val host = runCatching { request.httpService().host() }.getOrNull()
                        val raw = String(request.toByteArray().getBytes(), Charsets.ISO_8859_1)
                        RequestToBeSentAction.continueWith(HttpRequest.httpRequest(request.httpService(), SessionInjector.apply(raw, p, host)))
                    }.getOrDefault(RequestToBeSentAction.continueWith(request))
                }

                override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction {
                    // Auto-refresh a rotating token: on an in-scope scanner response with a trigger status, replay
                    // the login OFF this thread (debounced/single-flight) so subsequent scanner requests get the
                    // fresh token. Never block Burp's response pipeline on the login round-trip or regex scan.
                    val svc = refreshService
                    if (svc != null && runCatching { response.toolSource().isFromTool(ToolType.SCANNER) }.getOrDefault(false)) {
                        runCatching {
                            val status = response.statusCode().toInt()
                            if (svc.wantsRefresh(status) && api.scope().isInScope(response.initiatingRequest().url()) &&
                                refreshPending.compareAndSet(false, true)
                            ) {
                                Thread({ try { svc.refresh(force = false) } finally { refreshPending.set(false) } }, "revoltmcp-refresh")
                                    .apply { isDaemon = true }.start()
                            }
                        }
                    }
                    return ResponseReceivedAction.continueWith(response)
                }
            })
        }.onFailure { api.logging().logToError("Scanner session HTTP handler registration failed: ${it.message}") }

        // 2. Optional explicit session-handling action (for a user-defined rule + login macro).
        runCatching {
            registrations += api.http().registerSessionHandlingAction(object : SessionHandlingAction {
                override fun name(): String = "Revolt MCP: inject session profile"

                override fun performAction(actionData: SessionHandlingActionData): ActionResult {
                    val p = profile()
                    val req = actionData.request()
                    if (p.isEmpty) return ActionResult.actionResult(req)
                    return runCatching {
                        val host = runCatching { req.httpService().host() }.getOrNull()
                        val raw = String(req.toByteArray().getBytes(), Charsets.ISO_8859_1)
                        ActionResult.actionResult(HttpRequest.httpRequest(req.httpService(), SessionInjector.apply(raw, p, host)))
                    }.getOrDefault(ActionResult.actionResult(req))
                }
            })
        }.onFailure { api.logging().logToError("Session-handling action registration failed: ${it.message}") }
    }

    fun stop() {
        registrations.forEach { runCatching { it.deregister() } }
        registrations.clear()
    }
}
