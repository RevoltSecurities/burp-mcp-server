package com.revoltsecurities.burpmcp.config

import com.revoltsecurities.burpmcp.integrations.ExternalMcpServerConfig
import kotlinx.serialization.Serializable
import java.security.SecureRandom
import java.util.Base64

/**
 * Persisted server configuration. Serialized to JSON in Burp Preferences.
 *
 * The [token] is held here in PLAINTEXT in memory; it is encrypted/decrypted at the persistence boundary
 * (see [SettingsStore]) so it never hits the preference store or logs in the clear.
 */
@Serializable
data class McpSettings(
    val enabled: Boolean = false,
    val transport: TransportMode = Defaults.DEFAULT_TRANSPORT,
    val host: String = Defaults.HOST,
    val port: Int = Defaults.PORT,
    /** Bearer token for HTTP transports. Empty = will be generated on first enable. */
    val token: String = "",
    /** Allowed Origin header values (DNS-rebinding defense). Empty = loopback-only default policy. */
    val allowedOrigins: List<String> = emptyList(),
    val maxConcurrentRequests: Int = Defaults.MAX_CONCURRENT_REQUESTS,
    val maxToolResultBytes: Int = Defaults.MAX_TOOL_RESULT_BYTES,
    /** Confine read tools to in-scope URLs and reject out-of-scope sends. */
    val scopeOnly: Boolean = false,
    /** Master switch: may any mutating ("unsafe") tool run at all. */
    val unsafeToolsEnabled: Boolean = false,
    /** Per-tool enable/disable overrides, keyed by tool id. Absent = tool's own default. */
    val toolToggles: Map<String, Boolean> = emptyMap(),
    /** External MCP servers to federate (expose their tools as `ext:<name>:<tool>`). */
    val externalMcpServers: List<ExternalMcpServerConfig> = emptyList(),
    /** Directory holding user payload wordlists that intruder_attack may reference by name. Empty = ~/.revolt-mcp/wordlists. */
    val wordlistsDir: String = "",
    /** Directory for the local .bambda script library. Empty = ~/.revolt-mcp/bambdas. */
    val bambdasDir: String = "",
    /** Reusable auth/session profile auto-applied to outbound requests (cookies/headers encrypted at rest). */
    val sessionProfile: SessionProfile = SessionProfile(),
    /** Optional auto-login config to refresh a rotating session token (request encrypted at rest). */
    val sessionLogin: SessionLogin = SessionLogin(),
) {
    fun sanitized(): McpSettings = copy(
        port = port.coerceIn(1, 65_535),
        maxConcurrentRequests = maxConcurrentRequests.coerceIn(1, 64),
        maxToolResultBytes = maxToolResultBytes.coerceIn(4_096, 4_000_000),
    )

    val tokenIsWeak: Boolean
        get() = token.length < Defaults.MIN_TOKEN_BYTES

    companion object {
        /** 32 cryptographically-random bytes, URL-safe base64 (no padding). */
        fun generateToken(): String {
            val bytes = ByteArray(Defaults.MIN_TOKEN_BYTES).also { SecureRandom().nextBytes(it) }
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }
    }
}
