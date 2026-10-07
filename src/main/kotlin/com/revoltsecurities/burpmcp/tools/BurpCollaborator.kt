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
data class CollaboratorPollResult(val secretKey: String, val interactions: List<InteractionDTO>)

/** Burp Collaborator operations (Professional) for OOB/blind verification. */
interface BurpCollaborator {
    /** Generate a payload; the returned secretKey is used later to poll for interactions. */
    fun generate(customData: String?): CollaboratorPayloadInfo
    /** Poll interactions for a prior secretKey; if [includeHttp], register HTTP evidence for get_http_message. */
    fun poll(secretKey: String, includeHttp: Boolean): CollaboratorPollResult
}
