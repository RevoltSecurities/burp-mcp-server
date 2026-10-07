package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.serialization.Serializable

/**
 * Typed metadata rows for list tools. Rows carry a stable `id` (resolve bytes via `get_http_message`) and
 * scalar fields only — never request/response bodies. This is the single biggest defense against context bloat.
 */
@Serializable
data class ProxyHistoryRow(
    val id: String,
    val index: Int,
    val method: String,
    val url: String,
    val host: String,
    val status: Int? = null,
    val mimeType: String? = null,
    val requestLength: Int,
    val responseLength: Int,
    val inScope: Boolean,
    val notes: String? = null,
)

@Serializable
data class SiteMapRow(
    val id: String,
    val url: String,
    val host: String,
    val method: String? = null,
    val status: Int? = null,
    val mimeType: String? = null,
    val responseLength: Int,
    val inScope: Boolean,
)

@Serializable
data class IssueRow(
    val id: String,
    val name: String,
    val severity: String,
    val confidence: String,
    val host: String,
    val baseUrl: String,
    val definitionId: String? = null,
    val evidenceCount: Int,
)

fun HttpExchange.toRow(): ProxyHistoryRow = ProxyHistoryRow(
    id = MessageRegistry.proxyHistoryId(index),
    index = index,
    method = method,
    url = url,
    host = host,
    status = statusCode,
    mimeType = mimeType,
    requestLength = requestLength,
    responseLength = responseLength,
    inScope = inScope,
    notes = notes,
)

fun SiteMapNode.toRow(): SiteMapRow = SiteMapRow(
    id = MessageRegistry.siteMapId(url),
    url = url,
    host = host,
    method = method,
    status = statusCode,
    mimeType = mimeType,
    responseLength = responseLength,
    inScope = inScope,
)

fun IssueRecord.toRow(): IssueRow = IssueRow(
    id = MessageRegistry.issueId(index),
    name = name,
    severity = severity,
    confidence = confidence,
    host = host,
    baseUrl = baseUrl,
    definitionId = definitionId,
    evidenceCount = evidenceCount,
)
