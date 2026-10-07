package com.revoltsecurities.burpmcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.json.JsonObject

/**
 * Registers [ToolSpec]s onto an SDK [Server], enforcing — on the MCP wire path itself — per-tool enable
 * toggles, Professional gating, and the unsafe master switch for mutating tools. (Fixing the reference
 * project's #1 defect, where these checks ran only on its local chat path, not for remote MCP callers.)
 */
class ToolRegistry(
    private val specs: List<ToolSpec>,
    private val isProfessional: Boolean,
    private val isEnabled: (ToolSpec) -> Boolean,
    private val unsafeEnabled: () -> Boolean,
    private val onToolCall: (String) -> Unit = {},
    private val log: (String) -> Unit,
) {
    fun registerOn(server: Server) {
        val active = specs
            .filter { !it.proOnly || isProfessional }
            .filter { isEnabled(it) }
        for (spec in active) {
            server.addTool(spec.id, spec.description, spec.inputSchema) { request ->
                dispatch(spec, request.arguments)
            }
        }
        log("Registered ${active.size}/${specs.size} MCP tools (professional=$isProfessional).")
    }

    private suspend fun dispatch(spec: ToolSpec, arguments: JsonObject?): CallToolResult {
        if (spec.mutating && !unsafeEnabled()) {
            return Results.error(
                "Tool '${spec.id}' changes Burp state or sends traffic, and unsafe mode is disabled. " +
                    "Enable unsafe tools in the extension settings to use it.",
            )
        }
        onToolCall(spec.id)
        return try {
            spec.handler(Args(arguments ?: JsonObject(emptyMap())))
        } catch (e: IllegalArgumentException) {
            Results.error("Invalid arguments for '${spec.id}': ${scrub(e.message)}")
        } catch (e: Exception) {
            // Sanitised: never leak stack traces / absolute paths to the client.
            Results.error("Tool '${spec.id}' failed: ${scrub(e.message) ?: e.javaClass.simpleName}")
        }
    }

    /** Strip the user's home directory from outward-facing error text (keep full detail in logs only). */
    private fun scrub(message: String?): String? {
        if (message == null) return null
        val home = runCatching { System.getProperty("user.home") }.getOrNull()
        return if (!home.isNullOrEmpty()) message.replace(home, "~") else message
    }
}
