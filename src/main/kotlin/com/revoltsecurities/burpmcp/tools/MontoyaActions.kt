package com.revoltsecurities.burpmcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import com.revoltsecurities.burpmcp.config.SessionProfile
import java.time.ZonedDateTime

/** Montoya-backed [BurpActions]. Isolated from tool logic; exercised live in Burp. */
class MontoyaActions(private val api: MontoyaApi) : BurpActions {

    override fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String): SentExchange {
        val service = HttpService.httpService(host, port, secure)
        // Ensure a Host header is present (its absence is a common "no response / status 0" cause). Only adds
        // when missing, so crafted smuggling/desync requests keep their own; session injection happens upstream.
        val request = HttpRequest.httpRequest(service, SessionInjector.apply(raw, EMPTY_PROFILE, host))
        val outcome = runCatching { api.http().sendRequest(request, httpMode(mode)) }
        val rr = outcome.getOrNull()
        val resp = if (rr != null && rr.hasResponse()) rr.response() else null
        return SentExchange(
            statusCode = resp?.statusCode()?.toInt(),
            mimeType = resp?.let { runCatching { it.headerValue("Content-Type") }.getOrNull() },
            requestBytes = request.toByteArray().getBytes(),
            responseBytes = resp?.toByteArray()?.getBytes(),
            error = when {
                outcome.isFailure -> "send failed: ${outcome.exceptionOrNull()?.message ?: outcome.exceptionOrNull()?.javaClass?.simpleName}"
                resp == null -> "no response (connection reset / TLS / timeout / wrong port or Host)"
                else -> null
            },
        )
    }

    override fun sendToRepeater(raw: String, host: String, port: Int, secure: Boolean, name: String?) {
        val request = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw)
        if (name.isNullOrEmpty()) api.repeater().sendToRepeater(request) else api.repeater().sendToRepeater(request, name)
    }

    override fun sendToIntruder(raw: String, host: String, port: Int, secure: Boolean, name: String?) {
        val request = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw)
        if (name.isNullOrEmpty()) api.intruder().sendToIntruder(request) else api.intruder().sendToIntruder(request, name)
    }

    override fun includeInScope(url: String) = api.scope().includeInScope(url)
    override fun excludeFromScope(url: String) = api.scope().excludeFromScope(url)

    override fun setIntercept(enabled: Boolean) {
        if (enabled) api.proxy().enableIntercept() else api.proxy().disableIntercept()
    }

    override fun isInterceptEnabled(): Boolean = api.proxy().isInterceptEnabled()

    override fun cookies(): List<CookieDTO> = api.http().cookieJar().cookies().map {
        CookieDTO(
            name = runCatching { it.name() }.getOrDefault(""),
            value = runCatching { it.value() }.getOrDefault(""),
            domain = runCatching { it.domain() }.getOrDefault(""),
            path = runCatching { it.path() }.getOrNull(),
        )
    }

    override fun setCookie(name: String, value: String, domain: String, path: String?, expiresEpochSec: Long?) {
        val expiry = expiresEpochSec?.let { ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond(it), java.time.ZoneOffset.UTC) }
            ?: ZonedDateTime.now().plusYears(1)
        api.http().cookieJar().setCookie(name, value, path ?: "/", domain, expiry)
    }

    override fun createIssue(issue: NewIssue): Boolean {
        val existing = runCatching { api.siteMap().issues() }.getOrDefault(emptyList())
        if (existing.any { it.name() == issue.name && it.baseUrl() == issue.baseUrl }) return false

        val service = HttpService.httpService(issue.host, issue.port, issue.secure)
        val evidence: List<HttpRequestResponse> = if (issue.requestRaw != null) {
            val req = HttpRequest.httpRequest(service, issue.requestRaw)
            val resp: HttpResponse? = issue.responseRaw?.let { HttpResponse.httpResponse(it) }
            listOf(if (resp != null) HttpRequestResponse.httpRequestResponse(req, resp) else HttpRequestResponse.httpRequestResponse(req, HttpResponse.httpResponse()))
        } else {
            emptyList()
        }
        val severity = severityOf(issue.severity)
        val audit: AuditIssue = AuditIssue.auditIssue(
            issue.name,
            issue.detail,
            issue.remediation,
            issue.baseUrl,
            severity,
            confidenceOf(issue.confidence),
            issue.background,
            "",
            severity,
            evidence,
        )
        api.siteMap().add(audit)
        return true
    }

    override fun sendParallel(requests: List<RawTarget>, mode: String): List<SentExchange> {
        if (requests.isEmpty()) return emptyList()
        val built = requests.map {
            HttpRequest.httpRequest(HttpService.httpService(it.host, it.port, it.secure), SessionInjector.apply(it.raw, EMPTY_PROFILE, it.host))
        }
        val outcome = runCatching { api.http().sendRequests(built, httpMode(mode)) }
        val results = outcome.getOrNull()
        if (results == null) {
            val reason = "batch send failed: ${outcome.exceptionOrNull()?.message ?: outcome.exceptionOrNull()?.javaClass?.simpleName}"
            return built.map { SentExchange(null, null, runCatching { it.toByteArray().getBytes() }.getOrDefault(ByteArray(0)), null, reason) }
        }
        return results.mapIndexed { i, rr ->
            val resp = if (rr.hasResponse()) rr.response() else null
            SentExchange(
                statusCode = resp?.statusCode()?.toInt(),
                mimeType = resp?.let { runCatching { it.headerValue("Content-Type") }.getOrNull() },
                requestBytes = runCatching { built[i].toByteArray().getBytes() }.getOrDefault(ByteArray(0)),
                responseBytes = resp?.let { runCatching { it.toByteArray().getBytes() }.getOrNull() },
                error = if (resp == null) "no response (connection reset / TLS / timeout / wrong port or Host)" else null,
            )
        }
    }

    override fun managedEngineAvailable(): Boolean =
        runCatching { api.http().javaClass.methods.any { it.name == "createRequestEngine" } }.getOrDefault(false)

    override fun addToSiteMap(raw: String, host: String, port: Int, secure: Boolean, responseRaw: String?) {
        val service = HttpService.httpService(host, port, secure)
        val req = HttpRequest.httpRequest(service, raw)
        val resp = if (responseRaw != null) HttpResponse.httpResponse(responseRaw) else HttpResponse.httpResponse()
        api.siteMap().add(HttpRequestResponse.httpRequestResponse(req, resp))
    }

    override fun sendToOrganizer(raw: String, host: String, port: Int, secure: Boolean) {
        val req = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw)
        api.organizer().sendToOrganizer(req)
    }

    override fun organizerItems(): List<OrganizerItemDTO> {
        // Organizer.items() is Burp 2026.7+ only; on older Burp return empty rather than hitting NoSuchMethodError.
        val organizer = api.organizer()
        if (organizer.javaClass.methods.none { it.name == "items" && it.parameterCount == 0 }) return emptyList()
        // OrganizerItem extends HttpRequestResponse, so each item also carries the captured request/response —
        // surface url/host/method/status/notes (all best-effort) so the row is actionable, not just an id.
        return runCatching { organizer.items() }.getOrDefault(emptyList())
            .map { item ->
                OrganizerItemDTO(
                    id = runCatching { item.id() }.getOrDefault(-1),
                    status = runCatching { item.status().name }.getOrDefault(""),
                    url = runCatching { item.url() }.getOrNull(),
                    host = runCatching { item.httpService()?.host() }.getOrNull(),
                    method = runCatching { item.request()?.method() }.getOrNull(),
                    httpStatus = runCatching { if (item.hasResponse()) item.response().statusCode().toInt() else null }.getOrNull(),
                    notes = runCatching { item.annotations()?.takeIf { it.hasNotes() }?.notes() }.getOrNull(),
                )
            }
    }

    override fun wsSend(host: String, path: String, secure: Boolean, message: String, waitMs: Long): WsSendResult {
        val creation = api.websockets().createWebSocket(HttpService.httpService(host, if (secure) 443 else 80, secure), path)
        val upgradeStatus = creation.upgradeResponse().map { it.statusCode().toInt() }.orElse(null)
        val ws = creation.webSocket().orElse(null)
            ?: return WsSendResult(false, upgradeStatus, emptyList(), "WebSocket upgrade failed: ${creation.status()}")
        val received = java.util.concurrent.CopyOnWriteArrayList<String>()
        runCatching {
            ws.registerMessageHandler(object : burp.api.montoya.websocket.extension.ExtensionWebSocketMessageHandler {
                override fun textMessageReceived(textMessage: burp.api.montoya.websocket.TextMessage) { received.add(textMessage.payload()) }
                override fun binaryMessageReceived(binaryMessage: burp.api.montoya.websocket.BinaryMessage) {}
            })
            ws.sendTextMessage(message)
            Thread.sleep(waitMs.coerceIn(0, 10_000))
            ws.close()
        }
        return WsSendResult(true, upgradeStatus, received.toList(), "sent; collected ${received.size} message(s)")
    }

    override fun importBCheck(script: String, enabled: Boolean): ImportOutcome {
        val r = api.scanner().bChecks().importBCheck(script, enabled)
        val status = r.status().name
        val errors = runCatching { r.importErrors() }.getOrDefault(emptyList())
        // Burp returns LOADED_WITH_ERRORS (not a FAILED status) for a broken script — treat that as not-ok.
        return ImportOutcome(status, errors, ok = importOk(status, errors))
    }

    override fun importBambda(script: String): ImportOutcome {
        val r = api.bambda().importBambda(script)
        val status = r.status().name
        val errors = runCatching { r.importErrors() }.getOrDefault(emptyList())
        return ImportOutcome(status, errors, ok = importOk(status, errors))
    }

    // "LOADED_WITHOUT_ERRORS" is ok; "LOADED_WITH_ERRORS" (or any non-empty error list) is not.
    private fun importOk(status: String, errors: List<String>): Boolean =
        errors.isEmpty() && !status.contains("WITH_ERROR", ignoreCase = true) &&
            !status.contains("FAIL", ignoreCase = true) && !status.contains("UNSUPPORTED", ignoreCase = true)

    override fun exportProjectOptions(): String = api.burpSuite().exportProjectOptionsAsJson()
    override fun importProjectOptions(json: String) = api.burpSuite().importProjectOptionsFromJson(json)
    override fun exportUserOptions(): String = api.burpSuite().exportUserOptionsAsJson()
    override fun importUserOptions(json: String) = api.burpSuite().importUserOptionsFromJson(json)

    override fun taskEngineGet(): String = api.burpSuite().taskExecutionEngine().state.name

    override fun taskEngineSet(state: String): String {
        val target = if (state.equals("paused", ignoreCase = true)) {
            burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
        } else {
            burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
        }
        api.burpSuite().taskExecutionEngine().state = target
        return api.burpSuite().taskExecutionEngine().state.name
    }

    override fun persistenceGet(key: String): String? = runCatching { api.persistence().extensionData().getString(key) }.getOrNull()
    override fun persistenceSet(key: String, value: String) { api.persistence().extensionData().setString(key, value) }
    override fun persistenceKeys(): List<String> = runCatching { api.persistence().extensionData().stringKeys().toList() }.getOrDefault(emptyList())

    override fun projectInfo(): ProjectInfo = ProjectInfo(
        name = runCatching { api.project().name() }.getOrDefault(""),
        id = runCatching { api.project().id() }.getOrDefault(""),
    )

    private fun httpMode(mode: String): HttpMode = when (mode.lowercase().replace("-", "_")) {
        "http1", "http_1" -> HttpMode.HTTP_1
        "http2", "http_2" -> HttpMode.HTTP_2
        "http2_ignore_alpn", "http_2_ignore_alpn" -> HttpMode.HTTP_2_IGNORE_ALPN
        else -> HttpMode.AUTO
    }

    private fun severityOf(s: String): AuditIssueSeverity = runCatching {
        AuditIssueSeverity.valueOf(s.uppercase())
    }.getOrDefault(AuditIssueSeverity.INFORMATION)

    private fun confidenceOf(c: String): AuditIssueConfidence = runCatching {
        AuditIssueConfidence.valueOf(c.uppercase())
    }.getOrDefault(AuditIssueConfidence.TENTATIVE)

    private companion object {
        // Empty profile → SessionInjector only fills a missing Host header (session injection runs at the tool layer).
        val EMPTY_PROFILE = SessionProfile()
    }
}
