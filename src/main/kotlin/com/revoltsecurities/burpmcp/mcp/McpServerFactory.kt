package com.revoltsecurities.burpmcp.mcp

import com.revoltsecurities.burpmcp.config.BurpEnv
import com.revoltsecurities.burpmcp.config.Defaults
import com.revoltsecurities.burpmcp.config.McpSettings
import com.revoltsecurities.burpmcp.config.SessionProfile
import com.revoltsecurities.burpmcp.integrations.ExternalClients
import com.revoltsecurities.burpmcp.integrations.IntegrationTools
import com.revoltsecurities.burpmcp.integrations.WebhookSender
import com.revoltsecurities.burpmcp.integrations.federatedToolSpecs
import com.revoltsecurities.burpmcp.events.EventBuffer
import com.revoltsecurities.burpmcp.output.MessageRegistry
import com.revoltsecurities.burpmcp.tools.ActionTools
import com.revoltsecurities.burpmcp.tools.EventTools
import com.revoltsecurities.burpmcp.tools.ToolMeta
import com.revoltsecurities.burpmcp.tools.AnalysisTools
import com.revoltsecurities.burpmcp.tools.BurpActions
import com.revoltsecurities.burpmcp.tools.BurpCollaborator
import com.revoltsecurities.burpmcp.tools.BurpDataSource
import com.revoltsecurities.burpmcp.tools.BurpScanner
import com.revoltsecurities.burpmcp.tools.ControlTools
import com.revoltsecurities.burpmcp.tools.ConvenienceTools
import com.revoltsecurities.burpmcp.tools.ExtraActionTools
import com.revoltsecurities.burpmcp.tools.HttpMessageTool
import com.revoltsecurities.burpmcp.tools.IntruderTools
import com.revoltsecurities.burpmcp.tools.RaceTools
import com.revoltsecurities.burpmcp.tools.ScanTools
import com.revoltsecurities.burpmcp.tools.ScopeGuard
import com.revoltsecurities.burpmcp.tools.SessionTools
import com.revoltsecurities.burpmcp.tools.ReadTools
import com.revoltsecurities.burpmcp.tools.Results
import com.revoltsecurities.burpmcp.tools.SchemaBuilder
import com.revoltsecurities.burpmcp.tools.ToolConfig
import com.revoltsecurities.burpmcp.tools.ToolRegistry
import com.revoltsecurities.burpmcp.tools.ToolSpec
import com.revoltsecurities.burpmcp.tools.UtilityTools
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities

/**
 * Builds the single shared MCP [Server] and registers every tool through one [ToolRegistry] (the single
 * source of truth). One Server instance backs all client sessions.
 */
class McpServerFactory(
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
    private val statusProvider: () -> McpServerStatus,
    private val log: (String) -> Unit,
) {
    fun build(): Server {
        val server = Server(
            Implementation(name = Defaults.EXTENSION_NAME, version = version),
            ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))),
        )
        ToolRegistry(
            specs = buildSpecs(),
            isProfessional = dataSource.isProfessional(),
            isEnabled = { spec -> settingsProvider().toolToggles[spec.id] ?: spec.defaultEnabled },
            unsafeEnabled = { settingsProvider().unsafeToolsEnabled },
            onToolCall = metrics::record,
            log = log,
        ).registerOn(server)
        return server
    }

    /** Lightweight metadata for the UI tool grid — derived from the SAME spec list that gets registered. */
    fun toolMetadata(): List<ToolMeta> = buildSpecs().map {
        ToolMeta(it.id, it.title, it.category, it.mutating, it.proOnly, it.defaultEnabled)
    }

    private fun cfg(): ToolConfig = ToolConfig(
        defaultLimit = Defaults.DEFAULT_PAGE_LIMIT,
        maxLimit = Defaults.MAX_PAGE_LIMIT,
        maxToolResultBytes = settingsProvider().maxToolResultBytes,
        defaultSliceBytes = Defaults.DEFAULT_BODY_SLICE_BYTES,
        maxSliceBytes = Defaults.DEFAULT_BODY_SLICE_BYTES * 8,
    )

    private fun buildSpecs(): List<ToolSpec> {
        val cfg = cfg()
        val guard = ScopeGuard({ settingsProvider().scopeOnly }, dataSource::isInScope)
        val sessionProfile = { settingsProvider().sessionProfile }
        return buildList {
            add(statusTool())
            addAll(UtilityTools.build())
            addAll(AnalysisTools.build())
            addAll(ReadTools(dataSource, messageRegistry, cfg).build())
            add(HttpMessageTool.build(messageRegistry, cfg, dataSource))
            addAll(
                ActionTools(
                    actions = actions,
                    registry = messageRegistry,
                    scopeOnly = { settingsProvider().scopeOnly },
                    isInScope = dataSource::isInScope,
                    unsafeEnabled = { settingsProvider().unsafeToolsEnabled },
                    sessionProfile = sessionProfile,
                ).build(),
            )
            addAll(ScanTools(scanner, collaborator, dataSource, guard, sessionProfile).build())
            addAll(
                RaceTools(
                    actions = actions,
                    registry = messageRegistry,
                    scopeOnly = { settingsProvider().scopeOnly },
                    isInScope = dataSource::isInScope,
                    sessionProfile = sessionProfile,
                ).build(),
            )
            addAll(IntegrationTools(actions, webhook).build())
            addAll(EventTools.build(eventBuffer))
            addAll(ConvenienceTools(actions, messageRegistry, guard, sessionProfile).build())
            addAll(IntruderTools(actions, messageRegistry, guard, { settingsProvider().wordlistsDir }, sessionProfile).build())
            addAll(ExtraActionTools(actions, guard).build())
            addAll(ControlTools(actions).build())
            addAll(SessionTools(sessionProfile, sessionProfileUpdater, { settingsProvider().unsafeToolsEnabled }).build())
            addAll(federatedToolSpecs(externalClients))
        }
    }

    private fun statusTool(): ToolSpec =
        ToolSpec(
            id = "status",
            title = "Status",
            description = "Report Revolt MCP server + Burp status: version, edition, transport, running state.",
            category = "Config",
            inputSchema = SchemaBuilder.empty(),
        ) {
            val s = statusProvider()
            Results.text(
                buildString {
                    appendLine("server: ${Defaults.EXTENSION_NAME} v$version")
                    appendLine("burp: ${env.describe()}")
                    appendLine("state: ${s.state}")
                    appendLine("transport: ${s.transport}")
                    appendLine("url: ${s.boundUrl}")
                    append("active_sessions: ${s.activeSessions}")
                },
            )
        }
}
