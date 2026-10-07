package com.revoltsecurities.burpmcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import com.revoltsecurities.burpmcp.config.BurpEnv

/**
 * Montoya-backed [BurpDataSource]. Maps live Burp objects into the Montoya-free DTOs the tool logic uses.
 * Per-item mapping is guarded so one malformed entry can't fail an entire listing. Byte providers are lazy —
 * `toByteArray()` is only called when `get_http_message` asks for a slice.
 *
 * Not unit-tested (Montoya is provided by Burp at runtime); it is exercised live inside Burp.
 */
class MontoyaDataSource(private val api: MontoyaApi, private val env: BurpEnv) : BurpDataSource {

    override fun proxyHistory(): List<HttpExchange> =
        api.proxy().history().mapIndexedNotNull { index, p -> runCatching { toExchange(index, p) }.getOrNull() }

    override fun webSocketHistory(): List<WebSocketRecord> =
        api.proxy().webSocketHistory().mapIndexedNotNull { index, m -> runCatching { toWsRecord(index, m) }.getOrNull() }

    override fun siteMap(): List<SiteMapNode> =
        api.siteMap().requestResponses().mapNotNull { rr -> runCatching { toNode(rr) }.getOrNull() }

    override fun issues(): List<IssueRecord> =
        api.siteMap().issues().mapIndexedNotNull { index, i -> runCatching { toIssue(index, i) }.getOrNull() }

    override fun isInScope(url: String): Boolean = runCatching { api.scope().isInScope(url) }.getOrDefault(false)

    override fun burpVersion(): String = env.versionString

    override fun burpEdition(): String = env.edition.name

    override fun isProfessional(): Boolean = env.isProfessional

    // ---- mappers ----

    private fun toExchange(index: Int, p: ProxyHttpRequestResponse): HttpExchange {
        val resp: HttpResponse? = if (p.hasResponse()) p.response() else null
        val url = p.url()
        return HttpExchange(
            index = index,
            method = p.method(),
            url = url,
            host = p.host(),
            statusCode = resp?.statusCode()?.toInt(),
            mimeType = resp?.let { contentType(it) },
            requestLength = p.finalRequest().toByteArray().length(),
            responseLength = resp?.toByteArray()?.length() ?: 0,
            notes = p.annotations().takeIf { it.hasNotes() }?.notes(),
            inScope = isInScope(url),
            requestBytes = { kbytes(p.finalRequest().toByteArray()) },
            responseBytes = { if (p.hasResponse()) kbytes(p.response().toByteArray()) else null },
        )
    }

    private fun toNode(rr: HttpRequestResponse): SiteMapNode {
        val url = rr.url()
        val resp: HttpResponse? = if (rr.hasResponse()) rr.response() else null
        return SiteMapNode(
            url = url,
            host = rr.httpService().host(),
            method = runCatching { rr.request().method() }.getOrNull(),
            statusCode = resp?.statusCode()?.toInt(),
            mimeType = resp?.let { contentType(it) },
            responseLength = resp?.toByteArray()?.length() ?: 0,
            inScope = isInScope(url),
            requestBytes = { runCatching { kbytes(rr.request().toByteArray()) }.getOrNull() },
            responseBytes = { if (rr.hasResponse()) kbytes(rr.response().toByteArray()) else null },
        )
    }

    private fun toIssue(index: Int, i: AuditIssue): IssueRecord {
        val evidence = runCatching { i.requestResponses() }.getOrDefault(emptyList())
        val first = evidence.firstOrNull()
        return IssueRecord(
            index = index,
            name = i.name(),
            severity = i.severity().name,
            confidence = i.confidence().name,
            host = runCatching { i.httpService()?.host() }.getOrNull() ?: hostOf(i.baseUrl()),
            baseUrl = i.baseUrl(),
            definitionId = runCatching { i.definition()?.name() }.getOrNull(),
            detail = runCatching { i.detail() }.getOrNull(),
            remediation = runCatching { i.remediation() }.getOrNull(),
            background = null,
            evidenceCount = evidence.size,
            firstEvidenceRequest = first?.let { ev -> { runCatching { kbytes(ev.request().toByteArray()) }.getOrNull() } },
            firstEvidenceResponse = first?.let { ev ->
                { if (ev.hasResponse()) runCatching { kbytes(ev.response().toByteArray()) }.getOrNull() else null }
            },
        )
    }

    private fun toWsRecord(index: Int, m: ProxyWebSocketMessage): WebSocketRecord {
        val upgrade = runCatching { m.upgradeRequest() }.getOrNull()
        return WebSocketRecord(
            index = index,
            url = runCatching { upgrade?.url() }.getOrNull() ?: "",
            host = runCatching { upgrade?.httpService()?.host() }.getOrNull() ?: "",
            direction = m.direction().name,
            length = m.payload().length(),
            payloadBytes = { kbytes(m.payload()) },
        )
    }

    private fun contentType(resp: HttpResponse): String? =
        runCatching { resp.headerValue("Content-Type") }.getOrNull()

    private fun hostOf(url: String): String = runCatching { java.net.URI(url).host ?: "" }.getOrDefault("")

    private fun kbytes(b: BurpByteArray): kotlin.ByteArray = b.getBytes()
}
