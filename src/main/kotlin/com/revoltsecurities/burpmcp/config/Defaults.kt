package com.revoltsecurities.burpmcp.config

/** Centralised default values and limits. Keep every magic number here. */
object Defaults {
    const val EXTENSION_NAME = "Revolt MCP Server"
    const val VERSION = "0.4.0"

    // ---- Server ----
    const val HOST = "127.0.0.1"
    const val PORT = 9876
    const val MIN_TOKEN_BYTES = 32

    // ---- Transport ----
    val DEFAULT_TRANSPORT = TransportMode.STREAMABLE_HTTP
    const val STREAMABLE_PATH = "/mcp"
    const val SSE_PATH = "/sse"
    const val MESSAGE_PATH = "/message"

    // ---- Output / context management (Phase 2) ----
    const val DEFAULT_PAGE_LIMIT = 50
    const val MAX_PAGE_LIMIT = 100
    const val DEFAULT_BODY_SLICE_BYTES = 8_192
    const val MAX_TOOL_RESULT_BYTES = 96_000 // ~25k tokens * ~4 bytes, whole-envelope budget

    // ---- Concurrency ----
    const val MAX_CONCURRENT_REQUESTS = 8

    // ---- Preferences keys ----
    const val PREF_SETTINGS = "revoltmcp.settings.v1"
    const val PREF_MASTER_KEY = "revoltmcp.secret.masterkey.v1"
}

/** Selectable MCP transport formats. */
enum class TransportMode {
    STREAMABLE_HTTP,
    SSE,
    STDIO,
}
