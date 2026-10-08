package com.revoltsecurities.burpmcp.extension

import burp.api.montoya.MontoyaApi
import com.revoltsecurities.burpmcp.config.BurpEnv
import com.revoltsecurities.burpmcp.config.Defaults
import com.revoltsecurities.burpmcp.config.SettingsStore
import com.revoltsecurities.burpmcp.events.EventBuffer
import com.revoltsecurities.burpmcp.events.MontoyaEventSource
import com.revoltsecurities.burpmcp.integrations.GithubBambdaRepo
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
    private var sessionHandling: MontoyaSessionHandling? = null
    private var bambdaRepo: GithubBambdaRepo? = null

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
        // Persist session-profile / login changes so they survive restarts and agent context loss.
        val sessionProfileUpdater = { profile: com.revoltsecurities.burpmcp.config.SessionProfile ->
            settings.save(settings.current.copy(sessionProfile = profile)); Unit
        }
        val sessionLoginUpdater = { login: com.revoltsecurities.burpmcp.config.SessionLogin ->
            settings.save(settings.current.copy(sessionLogin = login)); Unit
        }
        // Native session auto-refresh: replay the login + rotate the token into the profile on 401/403.
        // Scope-gated like every other send tool — the login host must be in scope when confinement is on.
        val loginScopeGuard = com.revoltsecurities.burpmcp.tools.ScopeGuard({ settings.current.scopeOnly }, dataSource::isInScope)
        val refreshService = com.revoltsecurities.burpmcp.tools.SessionRefreshService(
            send = { raw, host, port, secure -> actions.sendRequest(raw, host, port, secure, "auto") },
            loginProvider = { settings.current.sessionLogin },
            currentProfile = { settings.current.sessionProfile },
            updateProfile = sessionProfileUpdater,
            scopeAllows = { host, port, secure -> loginScopeGuard.reject(host, port, secure) == null },
        )
        // Inject the stored session profile into in-scope scanner traffic + auto-refresh on trigger statuses.
        sessionHandling = MontoyaSessionHandling(api, { settings.current.sessionProfile }, refreshService).also { it.start() }
        val repo = GithubBambdaRepo()
        bambdaRepo = repo
        supervisor = McpServerSupervisor(
            env, Defaults.VERSION, dataSource, actions, scanner, collaborator, external, webhook,
            eventBuffer, metrics, messageRegistry, { settings.current }, sessionProfileUpdater,
            sessionLoginUpdater, refreshService, repo,
        ) { api.logging().logToOutput(it) }

        api.logging().logToOutput("${Defaults.EXTENSION_NAME} v${Defaults.VERSION} loading — ${env.describe()}")

        val mainTab = MainTab(env, settings, supervisor, refreshService)
        api.userInterface().registerSuiteTab(Defaults.EXTENSION_NAME, mainTab.component)

        // Auto-start if the user previously enabled the server.
        if (settings.current.enabled) {
            supervisor.start(settings.current)
        }

        api.logging().logToOutput("${Defaults.EXTENSION_NAME} initialized.")
    }

    fun shutdown() {
        if (::supervisor.isInitialized) supervisor.shutdown()
        sessionHandling?.stop()
        eventSource?.stop()
        externalClients?.shutdown()
        webhookSender?.close()
        bambdaRepo?.close()
        api.logging().logToOutput("${Defaults.EXTENSION_NAME} unloaded.")
    }
}
