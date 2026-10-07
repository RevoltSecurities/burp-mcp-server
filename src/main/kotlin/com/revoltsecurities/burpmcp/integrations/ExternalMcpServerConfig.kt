package com.revoltsecurities.burpmcp.integrations

import kotlinx.serialization.Serializable

enum class ExternalTransport { SSE, STREAMABLE_HTTP }

/** Configuration for an external MCP server we federate (act as a client to). */
@Serializable
data class ExternalMcpServerConfig(
    val name: String,
    val transport: ExternalTransport = ExternalTransport.STREAMABLE_HTTP,
    val url: String = "",
    /** Optional bearer token sent to the external server. Encrypted at rest alongside other secrets. */
    val token: String = "",
    val enabled: Boolean = true,
)
