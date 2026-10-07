package com.revoltsecurities.burpmcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.SecretKey
import com.revoltsecurities.burpmcp.output.MessageRegistry
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Montoya-backed [BurpCollaborator]. Caches clients by secret key AND persists every generated secret key via
 * [CollaboratorKeyStore], so a poll can restore clients even after the key fell out of the agent's context
 * (long autonomous runs / compaction). Professional-only.
 */
class MontoyaCollaborator(
    private val api: MontoyaApi,
    private val registry: MessageRegistry,
) : BurpCollaborator {

    private val clients = ConcurrentHashMap<String, CollaboratorClient>()
    private val evidenceCounter = AtomicInteger(0)
    private val keyStore = CollaboratorKeyStore(
        get = { runCatching { api.persistence().extensionData().getString(it) }.getOrNull() },
        set = { k, v -> runCatching { api.persistence().extensionData().setString(k, v) } },
    )

    override fun generate(customData: String?): CollaboratorPayloadInfo {
        val client = api.collaborator().createClient()
        val payload = if (customData.isNullOrEmpty()) client.generatePayload() else client.generatePayload(customData)
        val key = client.secretKey.toString()
        clients[key] = client
        keyStore.remember(key) // auto-save so polls never need the key supplied back
        return CollaboratorPayloadInfo(
            payload = payload.toString(),
            interactionId = payload.id().toString(),
            secretKey = key,
            note = "Payload saved. Poll with collaborator_poll (no args to poll ALL saved payloads, or pass interactionId to filter).",
        )
    }

    override fun poll(secretKey: String?, includeHttp: Boolean, interactionId: String?): CollaboratorPollResult {
        val keys = if (secretKey != null) listOf(secretKey) else keyStore.all()
        if (keys.isEmpty()) {
            return CollaboratorPollResult(emptyList(), 0, "No Collaborator payloads to poll. Generate one with collaborator_generate.")
        }
        val all = mutableListOf<InteractionDTO>()
        var polled = 0
        var skipped = 0
        for (key in keys) {
            // A persisted key can be stale (Burp restart / changed Collaborator server). Skip it instead of
            // letting one bad restore abort the whole poll — that would defeat the context-loss resilience.
            val client = clients[key]
                ?: runCatching { api.collaborator().restoreClient(SecretKey.secretKey(key)) }.getOrNull()?.also { clients[key] = it }
            if (client == null) { skipped++; continue }
            polled++
            runCatching { client.allInteractions }.getOrDefault(emptyList()).forEach { i ->
                if (interactionId == null || i.id().toString() == interactionId) all += toDto(i, includeHttp)
            }
        }
        val note = buildString {
            append("Polled $polled Collaborator client(s); ${all.size} interaction(s).")
            if (secretKey == null) append(" (all saved payloads)")
            if (skipped > 0) append(" $skipped stale key(s) skipped")
            if (interactionId != null) append(" filtered to interactionId=$interactionId")
        }
        return CollaboratorPollResult(all, polled, note)
    }

    private fun toDto(i: Interaction, includeHttp: Boolean): InteractionDTO {
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
        return InteractionDTO(
            id = i.id().toString(),
            type = i.type().name,
            timestamp = i.timeStamp().toString(),
            clientIp = runCatching { i.clientIp().hostAddress }.getOrDefault(""),
            customData = i.customData().orElse(null),
            evidenceId = evidenceId,
        )
    }
}
