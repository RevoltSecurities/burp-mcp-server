package com.revoltsecurities.burpmcp.tools

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema

/**
 * Single source of truth for a tool: metadata + input schema + handler. The registry turns a list of these
 * into SDK registrations, so schema, dispatch, and catalog never drift (the reference project hand-synced
 * three parallel tables).
 *
 * @param mutating true for tools that change Burp state or send traffic; gated by the unsafe master switch
 *   (and, in Phase 4, per-call approval) on EVERY path including the MCP wire path.
 * @param proOnly true for tools that need Burp Professional (Scanner, Collaborator); hidden in Community.
 */
class ToolSpec(
    val id: String,
    val title: String,
    val description: String,
    val category: String,
    val inputSchema: ToolSchema,
    val mutating: Boolean = false,
    val proOnly: Boolean = false,
    val defaultEnabled: Boolean = true,
    val handler: suspend (Args) -> io.modelcontextprotocol.kotlin.sdk.types.CallToolResult,
)
