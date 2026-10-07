package com.revoltsecurities.burpmcp.integrations

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonObject

/** A federated tool, already namespaced as `ext:<server>:<tool>`, carrying the external tool's own input schema. */
data class ExtToolDescriptor(val name: String, val description: String, val inputSchema: ToolSchema? = null)

/** Seam over the federated external MCP servers, so tool logic stays testable. */
interface ExternalClients {
    /** Snapshot of currently-available federated tools (namespaced). */
    fun availableTools(): List<ExtToolDescriptor>

    /** Call a federated tool by its namespaced name; returns trust-wrapped text (or an error string). */
    suspend fun call(fullName: String, args: JsonObject): String
}

/** Default when no external servers are configured. */
object NoExternalClients : ExternalClients {
    override fun availableTools(): List<ExtToolDescriptor> = emptyList()
    override suspend fun call(fullName: String, args: JsonObject): String = "No external MCP servers are configured."
}
