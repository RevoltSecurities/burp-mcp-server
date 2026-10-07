package com.revoltsecurities.burpmcp.mcp

import com.revoltsecurities.burpmcp.config.BurpEnv
import com.revoltsecurities.burpmcp.config.Defaults
import com.revoltsecurities.burpmcp.config.McpSettings
import com.revoltsecurities.burpmcp.config.SessionLogin
import com.revoltsecurities.burpmcp.config.SessionProfile
import com.revoltsecurities.burpmcp.config.TransportMode
import com.revoltsecurities.burpmcp.tools.SessionRefreshService
import com.revoltsecurities.burpmcp.output.MessageRegistry
import com.revoltsecurities.burpmcp.events.EventBuffer
import com.revoltsecurities.burpmcp.integrations.ExternalClients
import com.revoltsecurities.burpmcp.integrations.WebhookSender
import com.revoltsecurities.burpmcp.tools.BurpActions
import com.revoltsecurities.burpmcp.tools.ToolMeta
import com.revoltsecurities.burpmcp.tools.BurpCollaborator
import com.revoltsecurities.burpmcp.tools.BurpDataSource
import com.revoltsecurities.burpmcp.tools.BurpScanner
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Owns the embedded MCP server lifecycle: builds the chosen transport via [installMcpModule], and exposes
 * start/stop/restart + status to the UI. All start/stop work runs off the Swing EDT. One shared [Server]
 * (from [McpServerFactory]) backs every session.
 */
class McpServerSupervisor(
    private val env: BurpEnv,
    private val version: String,
    private val dataSource: BurpDataSource,
    private val actions: BurpActions,
    private val scanner: BurpScanner,
    private val collaborator: BurpCollaborator,
    private val externalClients: ExternalClients,
    private val webhook: WebhookSender,
    private val eventBuffer: EventBuffer,
    private val metrics: Metrics,
    private val messageRegistry: MessageRegistry,
    private val settingsProvider: () -> McpSettings,
    private val sessionProfileUpdater: (SessionProfile) -> Unit,
    private val sessionLoginUpdater: (SessionLogin) -> Unit,
    private val refreshService: SessionRefreshService,
    private val log: (String) -> Unit,
) {
    /** Tool-call counters for the dashboard. */
    val toolMetrics: Metrics get() = metrics
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val listeners = CopyOnWriteArrayList<(McpServerStatus) -> Unit>()

    @Volatile
    var status: McpServerStatus = McpServerStatus()
        private set

    private var engine: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>? = null

    fun addListener(listener: (McpServerStatus) -> Unit) {
        listeners += listener
        listener(status)
    }

    /** Idempotent start using the given settings. Safe to call from any thread. */
    @Synchronized
    fun start(settings: McpSettings) {
        if (status.state == McpServerState.RUNNING || status.state == McpServerState.STARTING) {
            log("MCP server already ${status.state}; ignoring start.")
            return
        }
        val clean = settings.sanitized()

        if (clean.transport == TransportMode.STDIO) {
            // stdio shares Burp's process-wide System.in/out — unusable in-JVM. Served by the external
            // bridge jar (Phase 8). Report clearly rather than corrupting Burp's streams.
            update(
                McpServerStatus(
                    state = McpServerState.ERROR,
                    transport = clean.transport.name,
                    lastError = "stdio runs via the external bridge (Phase 8). Choose streamable-http or sse for the in-Burp server.",
                ),
            )
            return
        }

        // Refuse to expose the full tool surface unauthenticated on a non-loopback interface.
        if (!isLoopbackHost(clean.host) && clean.token.isBlank()) {
            update(
                McpServerStatus(
                    state = McpServerState.ERROR,
                    transport = clean.transport.name,
                    lastError = "Refusing to bind non-loopback host '${clean.host}' without a bearer token. Generate a token (Server tab) or bind 127.0.0.1.",
                ),
            )
            return
        }

        update(status.copy(state = McpServerState.STARTING, transport = clean.transport.name, lastError = null))

        runCatching {
            val authGate = AuthGate(clean.token)
            val sharedServer: Server = buildFactory().build()
            val url = boundUrl(clean)

            val newEngine = embeddedServer(Netty, port = clean.port, host = clean.host) {
                installMcpModule(
                    transport = clean.transport,
                    authGate = authGate,
                    allowedOrigins = clean.allowedOrigins,
                    serverProvider = { sharedServer },
                    requireLoopbackHost = clean.token.isBlank(),
                )
            }
            engine = newEngine // assign before start() so a start failure (e.g. port in use) is cleaned up
            newEngine.start(wait = false)
            update(
                McpServerStatus(
                    state = McpServerState.RUNNING,
                    transport = clean.transport.name,
                    boundUrl = url,
                    activeSessions = 0,
                ),
            )
            log("MCP server started: ${clean.transport} on $url")
        }.onFailure { e ->
            runCatching { engine?.stop(0, 0) } // release Netty threads if start() failed after creation
            engine = null
            update(
                McpServerStatus(
                    state = McpServerState.ERROR,
                    transport = clean.transport.name,
                    lastError = e.message ?: e.javaClass.simpleName,
                ),
            )
            log("MCP server failed to start: ${e.message}")
        }
    }

    @Synchronized
    fun stop() {
        val e = engine
        engine = null
        if (e != null) {
            runCatching { e.stop(STOP_GRACE_MS, STOP_TIMEOUT_MS) }
                .onFailure { log("Error stopping MCP server: ${it.message}") }
        }
        update(McpServerStatus(state = McpServerState.STOPPED))
        log("MCP server stopped.")
    }

    @Synchronized
    fun restart(settings: McpSettings) {
        stop()
        start(settings)
    }

    fun shutdown() {
        stop()
        scope.cancel()
    }

    /** Tool metadata for the UI grid (reuses the real spec list). Safe to call before the server starts. */
    fun toolMetadata(): List<ToolMeta> = runCatching { buildFactory().toolMetadata() }.getOrDefault(emptyList())

    private fun buildFactory(): McpServerFactory = McpServerFactory(
        env = env,
        version = version,
        dataSource = dataSource,
        actions = actions,
        scanner = scanner,
        collaborator = collaborator,
        externalClients = externalClients,
        webhook = webhook,
        eventBuffer = eventBuffer,
        metrics = metrics,
        messageRegistry = messageRegistry,
        settingsProvider = settingsProvider,
        sessionProfileUpdater = sessionProfileUpdater,
        sessionLoginUpdater = sessionLoginUpdater,
        refreshService = refreshService,
        statusProvider = { status },
        log = log,
    )

    private fun boundUrl(settings: McpSettings): String {
        val suffix = when (settings.transport) {
            TransportMode.STREAMABLE_HTTP -> Defaults.STREAMABLE_PATH
            TransportMode.SSE -> Defaults.SSE_PATH
            TransportMode.STDIO -> ""
        }
        return "http://${settings.host}:${settings.port}$suffix"
    }

    private fun update(next: McpServerStatus) {
        status = next
        listeners.forEach { runCatching { it(next) } }
    }

    companion object {
        private const val STOP_GRACE_MS = 500L
        private const val STOP_TIMEOUT_MS = 2_000L
    }
}
