package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

@Serializable
data class CollaboratorPayloadInfo(
    val payload: String,
    val interactionId: String,
    val secretKey: String,
    val note: String,
)

@Serializable
data class InteractionDTO(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val customData: String? = null,
    val evidenceId: String? = null,
)

@Serializable
data class CollaboratorPollResult(
    val interactions: List<InteractionDTO>,
    val clientsPolled: Int = 1,
    val note: String = "",
)

/** Burp Collaborator operations (Professional) for OOB/blind verification. */
interface BurpCollaborator {
    /** Generate a payload; its secret key is auto-persisted so polls never need it supplied back. */
    fun generate(customData: String?): CollaboratorPayloadInfo
    /**
     * Poll interactions. [secretKey] null = poll ALL auto-remembered clients (survives context loss); otherwise
     * just that one. [interactionId] optionally filters to a single interaction id. [includeHttp] registers HTTP
     * evidence for get_http_message.
     */
    fun poll(secretKey: String?, includeHttp: Boolean, interactionId: String? = null): CollaboratorPollResult
}
