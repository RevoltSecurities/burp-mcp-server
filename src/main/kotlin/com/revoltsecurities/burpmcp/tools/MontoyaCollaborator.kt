package com.revoltsecurities.burpmcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.SecretKey
import com.revoltsecurities.burpmcp.output.MessageRegistry
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/** Montoya-backed [BurpCollaborator]; caches clients by secret key so polls can restore. Professional-only. */
class MontoyaCollaborator(
    private val api: MontoyaApi,
    private val registry: MessageRegistry,
) : BurpCollaborator {

    private val clients = ConcurrentHashMap<String, CollaboratorClient>()
    private val evidenceCounter = AtomicInteger(0)

    override fun generate(customData: String?): CollaboratorPayloadInfo {
        val client = api.collaborator().createClient()
        val payload = if (customData.isNullOrEmpty()) client.generatePayload() else client.generatePayload(customData)
        val key = client.secretKey.toString()
        clients[key] = client
        return CollaboratorPayloadInfo(
            payload = payload.toString(),
            interactionId = payload.id().toString(),
            secretKey = key,
            note = "Inject the payload host into a target; poll with collaborator_poll secretKey=$key.",
        )
    }

    override fun poll(secretKey: String, includeHttp: Boolean): CollaboratorPollResult {
        val client = clients.getOrPut(secretKey) { api.collaborator().restoreClient(SecretKey.secretKey(secretKey)) }
        val dtos = client.allInteractions.map { i ->
            var evidenceId: String? = null
            if (includeHttp) {
                i.httpDetails().ifPresent { d ->
                    val rr = d.requestResponse()
                    val id = "collab:${evidenceCounter.incrementAndGet()}"
                    registry.put(
                        MessageRegistry.Handle(
                            id, null,
                            { runCatching { rr.request().toByteArray().getBytes() }.getOrNull() },
                            { if (rr.hasResponse()) runCatching { rr.response().toByteArray().getBytes() }.getOrNull() else null },
                        ),
                    )
                    evidenceId = id
                }
            }
            InteractionDTO(
                id = i.id().toString(),
                type = i.type().name,
                timestamp = i.timeStamp().toString(),
                clientIp = runCatching { i.clientIp().hostAddress }.getOrDefault(""),
                customData = i.customData().orElse(null),
                evidenceId = evidenceId,
            )
        }
        return CollaboratorPollResult(secretKey, dtos)
    }
}
