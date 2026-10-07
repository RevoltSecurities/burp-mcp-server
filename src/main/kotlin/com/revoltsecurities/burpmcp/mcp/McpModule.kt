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

/** True for loopback hostnames/literals. */
fun isLoopbackHost(host: String): Boolean {
    val h = host.trim().removeSurrounding("[", "]").lowercase()
    return h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1" || h.startsWith("127.")
}

private fun originHost(origin: String): String? =
    runCatching { java.net.URI(origin).host?.removeSurrounding("[", "]") }.getOrNull()

private fun hostHeaderHost(hostHeader: String): String {
    val h = hostHeader.trim()
    return if (h.startsWith("[")) h.substringAfter("[").substringBefore("]") // [::1]:port
    else h.substringBefore(":")
}
