package com.revoltsecurities.burpmcp.integrations

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.sse.SSE
import io.ktor.client.request.header
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.ClientOptions
import io.modelcontextprotocol.kotlin.sdk.client.SseClientTransport
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import java.util.concurrent.ConcurrentHashMap

/**
 * Federates external MCP servers (SSE transport) via the SDK client. Each server's tools are re-exposed as
 * `ext:<name>:<tool>`; results are trust-boundary wrapped. Connection failures are isolated (SupervisorJob)
 * so a bad external server never affects our own tools.
 *
 * Compiled against the SDK but exercised only with a live external server. STREAMABLE_HTTP federation is a
 * follow-up (the SDK's streamable client transport ctor is ambiguous to call with defaults).
 */
class SdkExternalClients(
    private val configs: List<ExternalMcpServerConfig>,
    private val log: (String) -> Unit,
) : ExternalClients {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val clients = ConcurrentHashMap<String, Client>()
    private val httpClients = ConcurrentHashMap<String, HttpClient>()
    private val tools = ConcurrentHashMap<String, MutableList<ExtToolDescriptor>>()

    fun start() {
        configs.filter { it.enabled && it.url.isNotBlank() }.forEach { cfg ->
            if (cfg.transport != ExternalTransport.SSE) {
                log("External MCP '${cfg.name}': only SSE federation is supported currently; skipping ${cfg.transport}.")
                return@forEach
            }
            scope.launch { runCatching { connect(cfg) }.onFailure { log("External MCP '${cfg.name}' connect failed: ${it.message}") } }
        }
    }

    private suspend fun connect(cfg: ExternalMcpServerConfig) {
        val http = HttpClient(CIO) {
            install(SSE)
            if (cfg.token.isNotBlank()) install(DefaultRequest) { header("Authorization", "Bearer ${cfg.token}") }
        }
        httpClients[cfg.name] = http
        val client = Client(Implementation(name = "revolt-mcp-federation", version = "0.1.0"), ClientOptions())
        client.connect(SseClientTransport(http, cfg.url))
        clients[cfg.name] = client
        val listed = client.listTools()?.tools.orEmpty()
        tools[cfg.name] = listed.map {
            ExtToolDescriptor(Federation.namespaced(cfg.name, it.name), it.description ?: it.name, it.inputSchema)
        }.toMutableList()
        log("External MCP '${cfg.name}': connected, ${listed.size} tool(s) federated.")
    }

    override fun availableTools(): List<ExtToolDescriptor> = tools.values.flatten()

    override suspend fun call(fullName: String, args: JsonObject): String {
        val (server, tool) = Federation.parse(fullName) ?: return "Not a federated tool: $fullName"
        val client = clients[server] ?: return "External server '$server' is not connected."
        val result: CallToolResult = client.callTool(tool, args.mapValues { unwrap(it.value) })
            ?: return Federation.trustWrap(server, "(no result)")
        val text = result.content.filterIsInstance<TextContent>().joinToString("\n") { it.text }
        return Federation.trustWrap(server, text.ifEmpty { "(empty result)" })
    }

    fun shutdown() {
        httpClients.values.forEach { runCatching { it.close() } }
        scope.cancel()
    }

    private fun unwrap(e: JsonElement): Any? = when (e) {
        is JsonNull -> null
        is JsonPrimitive -> when {
            e.isString -> e.content
            e.booleanOrNull != null -> e.booleanOrNull
            e.longOrNull != null -> e.longOrNull
            e.doubleOrNull != null -> e.doubleOrNull
            else -> e.content
        }
        is JsonObject -> e.mapValues { unwrap(it.value) }
        is JsonArray -> e.map { unwrap(it) }
    }
}
