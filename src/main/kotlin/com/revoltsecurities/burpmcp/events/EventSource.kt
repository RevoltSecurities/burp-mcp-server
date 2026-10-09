package com.revoltsecurities.burpmcp.events

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction

/** Starts/stops the Burp event feed. */
interface EventSource {
    fun start()
    fun stop()
}

/**
 * Montoya-backed event feed: registers a pass-through HTTP handler (records every response seen across Burp)
 * and an audit-issue handler (records new scan issues), pushing lightweight summaries into the [EventBuffer].
 * Never mutates traffic — always continues with the original request/response.
 */
class MontoyaEventSource(
    private val api: MontoyaApi,
    private val buffer: EventBuffer,
) : EventSource {

    private val registrations = java.util.concurrent.CopyOnWriteArrayList<Registration>()

    override fun start() {
        // Each registration is guarded independently: the HTTP feed must still start even if the audit-issue
        // handler is unavailable. api.scanner() throws under Burp Community (Scanner is Professional-only), so
        // that registration is best-effort and its failure must never propagate into extension init.
        runCatching {
            registrations += api.http().registerHttpHandler(object : HttpHandler {
                override fun handleHttpRequestToBeSent(request: HttpRequestToBeSent): RequestToBeSentAction =
                    RequestToBeSentAction.continueWith(request)

                override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction {
                    runCatching {
                        val req = response.initiatingRequest()
                        buffer.record(
                            kind = "http",
                            summary = "${req.method()} ${req.url()} -> ${response.statusCode()}",
                            method = req.method(),
                            url = req.url(),
                            status = response.statusCode().toInt(),
                        )
                    }
                    return ResponseReceivedAction.continueWith(response)
                }
            })
        }

        runCatching {
            registrations += api.scanner().registerAuditIssueHandler { issue ->
                runCatching {
                    buffer.record(
                        kind = "issue",
                        summary = "${issue.severity().name}: ${issue.name()}",
                        url = issue.baseUrl(),
                        severity = issue.severity().name,
                    )
                }
            }
        }
    }

    override fun stop() {
        registrations.forEach { runCatching { it.deregister() } }
        registrations.clear()
    }
}
