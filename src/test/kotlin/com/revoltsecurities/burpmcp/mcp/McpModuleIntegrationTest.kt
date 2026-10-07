package com.revoltsecurities.burpmcp.mcp

import com.revoltsecurities.burpmcp.config.TransportMode
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.Timeout
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.TimeUnit

/**
 * End-to-end check of [installMcpModule]: boots a real Netty server with the streamable-HTTP transport +
 * bearer/Origin gate, then exercises it over HTTP. This is exactly the wiring the supervisor runs in Burp,
 * minus the Montoya-backed tools.
 *
 * Uses the JDK HttpClient (not the Ktor client) so every request has a hard per-call timeout and the
 * streaming initialize response is read headers-only — no hangs.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Timeout(value = 30, unit = TimeUnit.SECONDS)
class McpModuleIntegrationTest {

    private val port = 19_876
    private val token = "test-bearer-token-value-1234567890ab"
    private val base = "http://127.0.0.1:$port"
    private lateinit var engine: EmbeddedServer<*, *>
    private val http: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build()

    private val initializeBody = """
        {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"it-test","version":"1.0"}}}
    """.trimIndent()

    @BeforeAll
    fun startServer() {
        val server = Server(
            Implementation(name = "revolt-it", version = "0.0.0"),
            ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))),
        )
        server.addTool(name = "status", description = "test status tool") { _ ->
            CallToolResult(content = listOf(TextContent("ok")))
        }
        engine = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            installMcpModule(
                transport = TransportMode.STREAMABLE_HTTP,
                authGate = AuthGate(token),
                allowedOrigins = emptyList(),
                serverProvider = { server },
            )
        }
        engine.start(wait = false)
        waitForHealth()
    }

    @AfterAll
    fun stopServer() {
        engine.stop(200, 1_000)
    }

    @Test
    fun `health endpoint is open and returns ok`() {
        val resp = http.send(get("$base$MCP_HEALTH_PATH"), HttpResponse.BodyHandlers.ofString())
        assertEquals(200, resp.statusCode())
        assertEquals("ok", resp.body())
    }

    @Test
    fun `mcp endpoint rejects missing bearer token with 401`() {
        val resp = http.send(
            postJson("$base/mcp", initializeBody, origin = null, bearer = null),
            HttpResponse.BodyHandlers.ofString(),
        )
        assertEquals(401, resp.statusCode())
    }

    @Test
    fun `mcp endpoint rejects non-loopback Origin with 403`() {
        val resp = http.send(
            postJson("$base/mcp", initializeBody, origin = "http://evil.example.com", bearer = token),
            HttpResponse.BodyHandlers.ofString(),
        )
        assertEquals(403, resp.statusCode())
    }

    @Test
    fun `valid bearer token gets past the auth gate to the MCP handler`() {
        // Read headers only (discarding the possibly-streaming body) so this can never hang.
        val resp = http.send(
            postJson("$base/mcp", initializeBody, origin = null, bearer = token),
            HttpResponse.BodyHandlers.discarding(),
        )
        assertNotEquals(401, resp.statusCode(), "valid token must not be rejected by the gate")
        assertNotEquals(403, resp.statusCode(), "loopback request must not be Origin-blocked")
    }

    // ---- helpers ----

    private fun get(url: String): HttpRequest =
        HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(5)).GET().build()

    private fun postJson(url: String, body: String, origin: String?, bearer: String?): HttpRequest {
        val b = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
        if (origin != null) b.header("Origin", origin)
        if (bearer != null) b.header("Authorization", "Bearer $bearer")
        return b.build()
    }

    private fun waitForHealth() {
        repeat(50) {
            val ok = runCatching {
                http.send(get("$base$MCP_HEALTH_PATH"), HttpResponse.BodyHandlers.discarding()).statusCode() == 200
            }.getOrDefault(false)
            if (ok) return
            Thread.sleep(100)
        }
        error("server did not become healthy on $base")
    }
}
