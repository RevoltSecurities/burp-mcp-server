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
    private val client = HttpClient(CIO) { followRedirects = false } // don't let a 302 jump to an internal host
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

    /**
     * SSRF guard: RESOLVE the host and block if any resolved address is loopback/site-local/link-local/
     * any-local/multicast (covers decimal/hex/octal IPv4 notations, IPv6 bracket/mapped forms, and DNS names
     * that point at internal IPs). Fails CLOSED (blocks) if the host can't be resolved.
     */
    fun isBlockedHost(host: String): Boolean {
        val h = host.trim().removeSurrounding("[", "]").lowercase()
        if (h.isEmpty() || h == "localhost" || h.endsWith(".localhost")) return true
        return try {
            val addrs = java.net.InetAddress.getAllByName(h)
            addrs.isEmpty() || addrs.any { a ->
                a.isLoopbackAddress || a.isAnyLocalAddress || a.isLinkLocalAddress ||
                    a.isSiteLocalAddress || a.isMulticastAddress || isUniqueLocalV6(a)
            }
        } catch (_: Exception) {
            true // cannot resolve → do not send
        }
    }

    private fun isUniqueLocalV6(a: java.net.InetAddress): Boolean {
        val b = a.address
        return b.size == 16 && (b[0].toInt() and 0xFE) == 0xFC // fc00::/7
    }
}
