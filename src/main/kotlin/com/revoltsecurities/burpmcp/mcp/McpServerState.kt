package com.revoltsecurities.burpmcp.mcp

/** Observable lifecycle state of the embedded MCP server. */
enum class McpServerState {
    STOPPED,
    STARTING,
    RUNNING,
    ERROR,
}

/** Snapshot of server status for the UI / status tool. */
data class McpServerStatus(
    val state: McpServerState = McpServerState.STOPPED,
    val transport: String = "",
    val boundUrl: String = "",
    val activeSessions: Int = 0,
    val lastError: String? = null,
)
