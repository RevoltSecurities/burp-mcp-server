package com.revoltsecurities.burpmcp.mcp

import com.revoltsecurities.burpmcp.config.Defaults
import com.revoltsecurities.burpmcp.config.TransportMode
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.request.path
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.mcp
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp

/** Health endpoint path; exempt from auth so liveness probes work without a token. */
const val MCP_HEALTH_PATH: String = "/__health"

/**
 * Single source of truth for the embedded Ktor module: the bearer/Origin gate (ahead of routing), the
 * health route, and the selected MCP transport. Shared by [McpServerSupervisor] and the integration test
 * so what we test is exactly what runs in Burp.
 */
fun Application.installMcpModule(
    transport: TransportMode,
    authGate: AuthGate,
    allowedOrigins: List<String>,
    serverProvider: () -> Server,
    streamablePath: String = Defaults.STREAMABLE_PATH,
    requireLoopbackHost: Boolean = false,
) {
    @Suppress("DEPRECATION")
    intercept(ApplicationCallPipeline.Plugins) {
        val path = call.request.path()
        if (path == MCP_HEALTH_PATH) return@intercept

        // Origin check (DNS-rebinding/CSRF): exact host match, not a prefix (so 127.0.0.1.evil.com is rejected).
        val origin = call.request.headers["Origin"]
        if (origin != null) {
            val oh = originHost(origin)
            if (oh == null || (!isLoopbackHost(oh) && allowedOrigins.none { it == origin })) {
                call.respondText("Origin not allowed", status = HttpStatusCode.Forbidden)
                finish()
                return@intercept
            }
        }

        // Host-header check: for the tokenless loopback server, reject non-loopback Host (rebinding defense)
        // even when no Origin header is present.
        if (requireLoopbackHost) {
            val hostHeader = call.request.headers["Host"]
            if (hostHeader != null && !isLoopbackHost(hostHeaderHost(hostHeader))) {
                call.respondText("Host not allowed", status = HttpStatusCode.Forbidden)
                finish()
                return@intercept
            }
        }

        val denial = authGate.evaluate(call.request.headers["Authorization"])
        if (denial != null) {
            call.respondText(denial.message, status = HttpStatusCode.fromValue(denial.status))
            finish()
        }
    }

    routing {
        get(MCP_HEALTH_PATH) { call.respondText("ok") }
    }

    when (transport) {
        TransportMode.STREAMABLE_HTTP -> mcpStreamableHttp(streamablePath) { serverProvider() }
        TransportMode.SSE -> mcp { serverProvider() }
        TransportMode.STDIO -> error("stdio is not an HTTP module; handled by the external bridge")
    }
}

/**
 * True only for genuine loopback hostnames/literals. The IPv4 check is a **strict dotted-quad** parse of the
 * 127.0.0.0/8 range — never a `startsWith("127.")` prefix, which would misclassify an attacker-registered
 * name like `127.0.0.1.evil.com` (DNS-rebinding into `127.0.0.1`) as loopback and defeat the Origin/Host
 * gate. We never DNS-resolve the untrusted host string here (resolution would itself enable rebinding and
 * block); a non-literal name fails closed.
 */
fun isLoopbackHost(host: String): Boolean {
    val h = host.trim().removeSurrounding("[", "]").lowercase()
    if (h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1") return true
    val octets = h.split('.')
    if (octets.size != 4) return false
    if (octets.any { it.isEmpty() || it.length > 3 || !it.all(Char::isDigit) || it.toInt() !in 0..255 }) return false
    return octets[0].toInt() == 127
}

private fun originHost(origin: String): String? =
    runCatching { java.net.URI(origin).host?.removeSurrounding("[", "]") }.getOrNull()

private fun hostHeaderHost(hostHeader: String): String {
    val h = hostHeader.trim()
    return if (h.startsWith("[")) h.substringAfter("[").substringBefore("]") // [::1]:port
    else h.substringBefore(":")
}
