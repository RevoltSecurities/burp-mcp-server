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
) {
    @Suppress("DEPRECATION")
    intercept(ApplicationCallPipeline.Plugins) {
        val path = call.request.path()
        if (path == MCP_HEALTH_PATH) return@intercept

        val origin = call.request.headers["Origin"]
        if (origin != null && !isLoopbackOrigin(origin) && allowedOrigins.none { it == origin }) {
            call.respondText("Origin not allowed", status = HttpStatusCode.Forbidden)
            finish()
            return@intercept
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

private fun isLoopbackOrigin(origin: String): Boolean =
    origin.startsWith("http://127.0.0.1") ||
        origin.startsWith("http://localhost") ||
        origin.startsWith("https://127.0.0.1") ||
        origin.startsWith("https://localhost")
