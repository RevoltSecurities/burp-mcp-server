package com.revoltsecurities.burpmcp.integrations

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Seam for outbound webhook POSTs (Slack/Jira/generic). */
interface WebhookSender {
    /** @return HTTP status code of the POST. */
    suspend fun post(url: String, jsonBody: String): Int
}

class KtorWebhookSender : WebhookSender {
    private val client = HttpClient(CIO)
    override suspend fun post(url: String, jsonBody: String): Int {
        val resp: HttpResponse = client.post(url) {
            contentType(ContentType.Application.Json)
            setBody(jsonBody)
        }
        return resp.status.value
    }

    fun close() = client.close()
}

/** Pure payload builders + an SSRF guard for user-supplied webhook URLs. */
object Webhooks {
    private val json = Json

    fun slackPayload(text: String): String = json.encodeToString(
        kotlinx.serialization.json.JsonObject.serializer(),
        buildJsonObject { put("text", text) },
    )

    fun genericPayload(text: String): String = json.encodeToString(
        kotlinx.serialization.json.JsonObject.serializer(),
        buildJsonObject { put("text", text) },
    )

    /** Block private/loopback/link-local destinations to reduce SSRF via a user-supplied webhook URL. */
    fun isBlockedHost(host: String): Boolean {
        val h = host.lowercase()
        if (h == "localhost" || h.endsWith(".localhost")) return true
        if (h == "::1" || h == "0:0:0:0:0:0:0:1") return true
        val octets = h.split('.')
        if (octets.size == 4 && octets.all { it.toIntOrNull() in 0..255 }) {
            val a = octets[0].toInt(); val b = octets[1].toInt()
            return a == 127 || a == 10 || a == 0 ||
                (a == 192 && b == 168) ||
                (a == 169 && b == 254) ||
                (a == 172 && b in 16..31)
        }
        return h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")
    }
}
