package com.revoltsecurities.burpmcp.extension

import burp.api.montoya.MontoyaApi
import com.revoltsecurities.burpmcp.config.BurpEnv
import com.revoltsecurities.burpmcp.config.Defaults
import com.revoltsecurities.burpmcp.config.SettingsStore
import com.revoltsecurities.burpmcp.events.EventBuffer
import com.revoltsecurities.burpmcp.events.MontoyaEventSource
import com.revoltsecurities.burpmcp.integrations.KtorWebhookSender
import com.revoltsecurities.burpmcp.integrations.SdkExternalClients
import com.revoltsecurities.burpmcp.mcp.McpServerSupervisor
import com.revoltsecurities.burpmcp.mcp.Metrics
import com.revoltsecurities.burpmcp.output.MessageRegistry
import com.revoltsecurities.burpmcp.tools.MontoyaActions
import com.revoltsecurities.burpmcp.tools.MontoyaCollaborator
import com.revoltsecurities.burpmcp.tools.MontoyaDataSource
import com.revoltsecurities.burpmcp.tools.MontoyaScanner
import com.revoltsecurities.burpmcp.ui.MainTab

/**
 * Central bootstrap. Owns construction order and teardown of every subsystem, so [BurpMcpExtension]
 * stays a thin shell.
 */
class App(private val api: MontoyaApi) {

    private lateinit var env: BurpEnv
    private lateinit var settings: SettingsStore
    private lateinit var supervisor: McpServerSupervisor
    private var externalClients: SdkExternalClients? = null
    private var webhookSender: KtorWebhookSender? = null
    private var eventSource: MontoyaEventSource? = null

    fun initialize() {
        api.extension().setName(Defaults.EXTENSION_NAME)

        env = BurpEnv(api)
        settings = SettingsStore.create(api)
        val messageRegistry = MessageRegistry()
        val dataSource = MontoyaDataSource(api, env)
        val actions = MontoyaActions(api)
        val scanner = MontoyaScanner(api)
        val collaborator = MontoyaCollaborator(api, messageRegistry)
        val external = SdkExternalClients(settings.current.externalMcpServers) { api.logging().logToOutput(it) }
            .also { it.start() }
        externalClients = external
        val webhook = KtorWebhookSender()
        webhookSender = webhook
        val eventBuffer = EventBuffer()
        val metrics = Metrics()
        eventSource = MontoyaEventSource(api, eventBuffer).also { it.start() }
        supervisor = McpServerSupervisor(
            env, Defaults.VERSION, dataSource, actions, scanner, collaborator, external, webhook,
            eventBuffer, metrics, messageRegistry, { settings.current },
        ) { api.logging().logToOutput(it) }

        api.logging().logToOutput("${Defaults.EXTENSION_NAME} v${Defaults.VERSION} loading — ${env.describe()}")

        val mainTab = MainTab(env, settings, supervisor)
        api.userInterface().registerSuiteTab(Defaults.EXTENSION_NAME, mainTab.component)

        // Auto-start if the user previously enabled the server.
        if (settings.current.enabled) {
            supervisor.start(settings.current)
        }

        api.logging().logToOutput("${Defaults.EXTENSION_NAME} initialized.")
    }

    fun shutdown() {
        if (::supervisor.isInitialized) supervisor.shutdown()
        eventSource?.stop()
        externalClients?.shutdown()
        webhookSender?.close()
        api.logging().logToOutput("${Defaults.EXTENSION_NAME} unloaded.")
    }
}
