package com.revoltsecurities.burpmcp.tools

/**
 * Montoya-free DTOs for the data the read tools expose, plus the [BurpDataSource] seam. The Montoya-backed
 * implementation lives in `MontoyaDataSource`; the pure paging/filtering/row-mapping logic depends only on
 * these types, so it is unit-testable with a fake source.
 *
 * Byte providers are lazy: list tools never materialise bodies — only `get_http_message` pulls bytes.
 */
data class HttpExchange(
    val index: Int,
    val method: String,
    val url: String,
    val host: String,
    val statusCode: Int?,
    val mimeType: String?,
    val requestLength: Int,
    val responseLength: Int,
    val notes: String?,
    val inScope: Boolean,
    val requestBytes: () -> ByteArray?,
    val responseBytes: () -> ByteArray?,
)

data class SiteMapNode(
    val url: String,
    val host: String,
    val method: String?,
    val statusCode: Int?,
    val mimeType: String?,
    val responseLength: Int,
    val inScope: Boolean,
    val requestBytes: () -> ByteArray?,
    val responseBytes: () -> ByteArray?,
)

data class IssueRecord(
    val index: Int,
    val name: String,
    val severity: String,
    val confidence: String,
    val host: String,
    val baseUrl: String,
    val definitionId: String?,
    val detail: String?,
    val remediation: String?,
    val background: String?,
    val evidenceCount: Int,
    val firstEvidenceRequest: (() -> ByteArray?)? = null,
    val firstEvidenceResponse: (() -> ByteArray?)? = null,
)

/** Everything the read tools need from Burp, behind a seam so the tool logic is testable. */
interface BurpDataSource {
    fun proxyHistory(): List<HttpExchange>
    fun webSocketHistory(): List<WebSocketRecord>
    fun siteMap(): List<SiteMapNode>
    fun issues(): List<IssueRecord>
    fun isInScope(url: String): Boolean
    fun burpVersion(): String
    fun burpEdition(): String
    fun isProfessional(): Boolean
}

data class WebSocketRecord(
    val index: Int,
    val url: String,
    val host: String,
    val direction: String,
    val length: Int,
    val payloadBytes: () -> ByteArray?,
)
