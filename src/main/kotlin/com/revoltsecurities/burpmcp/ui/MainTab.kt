package com.revoltsecurities.burpmcp.ui

import com.revoltsecurities.burpmcp.config.BurpEnv
import com.revoltsecurities.burpmcp.config.McpSettings
import com.revoltsecurities.burpmcp.config.SettingsStore
import com.revoltsecurities.burpmcp.config.TransportMode
import com.revoltsecurities.burpmcp.mcp.McpServerState
import com.revoltsecurities.burpmcp.mcp.McpServerStatus
import com.revoltsecurities.burpmcp.mcp.McpServerSupervisor
import com.revoltsecurities.burpmcp.ui.components.StatusBadge
import com.revoltsecurities.burpmcp.ui.components.ToggleSwitch
import com.revoltsecurities.burpmcp.ui.design.DesignTokens
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.Timer

/**
 * The Revolt MCP console: a tabbed, theme-aware Swing UI (Dashboard / Server / Tools / Connect). Blends with
 * Burp's FlatLaf via [DesignTokens]. All blocking work (start/stop) runs off the EDT.
 */
class MainTab(
    private val env: BurpEnv,
    private val store: SettingsStore,
    private val supervisor: McpServerSupervisor,
) {
    private val headerBadge = StatusBadge("STOPPED")

    // server form
    private val transportBox = JComboBox(TransportMode.entries.toTypedArray())
    private val hostField = JTextField(16)
    private val portField = JTextField(6)
    private val tokenField = JTextField(28)
    private val enableBox = JCheckBox("Start automatically when the extension loads")
    private val unsafeBox = JCheckBox("Allow mutating tools (send, scope, cookies, scans, issues)")
    private val scopeBox = JCheckBox("Confine tools to in-scope targets only")
    private val startButton = JButton("Start")
    private val stopButton = JButton("Stop")

    // dashboard
    private val dashState = JLabel()
    private val dashTransport = JLabel()
    private val dashUrl = JLabel()
    private val dashCalls = JLabel()

    // tools
    private val toolToggles = linkedMapOf<String, ToggleSwitch>()
    private val toolSearch = JTextField(18)
    private val toolListPanel = JPanel().apply { layout = BoxLayout(this, BoxLayout.Y_AXIS) }

    // connect
    private val connectArea = JTextArea(12, 60).apply { isEditable = false; lineWrap = true; wrapStyleWord = true }

    val component: Component = buildRoot()

    init {
        loadFromSettings(store.current)
        rebuildToolRows()
        refreshConnect()
        supervisor.addListener { status -> SwingUtilities.invokeLater { renderStatus(status) } }
        startButton.addActionListener { onStart() }
        stopButton.addActionListener { onStop() }
        Timer(1000) { refreshDashboard() }.apply { isRepeats = true }.start()
    }

    private fun buildRoot(): JPanel {
        val root = JPanel(BorderLayout())
        root.border = BorderFactory.createEmptyBorder(DesignTokens.S4, DesignTokens.S4, DesignTokens.S4, DesignTokens.S4)

        val header = JPanel(BorderLayout())
        val title = JLabel("Revolt MCP Server").apply { font = DesignTokens.heading() }
        header.add(title, BorderLayout.WEST)
        header.add(JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0)).apply { isOpaque = false; add(headerBadge) }, BorderLayout.EAST)
        header.border = BorderFactory.createEmptyBorder(0, 0, DesignTokens.S3, 0)
        root.add(header, BorderLayout.NORTH)

        val tabs = JTabbedPane()
        tabs.addTab("Dashboard", dashboardTab())
        tabs.addTab("Server", serverTab())
        tabs.addTab("Tools", toolsTab())
        tabs.addTab("Connect", connectTab())
        root.add(tabs, BorderLayout.CENTER)

        renderStatus(supervisor.status)
        return root
    }

    // ---- Dashboard ----

    private fun dashboardTab(): JPanel {
        val p = JPanel(GridBagLayout())
        p.border = BorderFactory.createEmptyBorder(DesignTokens.S4, DesignTokens.S4, DesignTokens.S4, DesignTokens.S4)
        val c = GridBagConstraints().apply { insets = Insets(6, 6, 6, 6); anchor = GridBagConstraints.WEST }
        var row = 0
        fun add(label: String, value: JLabel) {
            c.gridx = 0; c.gridy = row; p.add(JLabel(label).apply { foreground = DesignTokens.textMuted }, c)
            c.gridx = 1; c.gridy = row; p.add(value, c); row++
        }
        add("Burp:", JLabel(env.describe()))
        add("State:", dashState)
        add("Transport:", dashTransport)
        add("URL:", dashUrl)
        add("Tool calls:", dashCalls)
        c.gridx = 0; c.gridy = row; c.gridwidth = 2
        p.add(JLabel("Live metrics refresh every second.").apply { foreground = DesignTokens.textMuted }, c)
        return p
    }

    private fun refreshDashboard() {
        val s = supervisor.status
        dashState.text = s.state.name
        dashTransport.text = s.transport
        dashUrl.text = s.boundUrl.ifEmpty { "—" }
        dashCalls.text = supervisor.toolMetrics.totalCalls().toString()
    }

    // ---- Server ----

    private fun serverTab(): JPanel {
        val form = JPanel(GridBagLayout())
        form.border = BorderFactory.createEmptyBorder(DesignTokens.S4, DesignTokens.S4, DesignTokens.S4, DesignTokens.S4)
        val c = GridBagConstraints().apply { insets = Insets(4, 4, 4, 4); anchor = GridBagConstraints.WEST }
        var row = 0
        fun labeled(label: String, field: Component) {
            c.gridx = 0; c.gridy = row; form.add(JLabel(label), c)
            c.gridx = 1; c.gridy = row; if (field is JTextField) field.preferredSize = Dimension(280, field.preferredSize.height)
            form.add(field, c); row++
        }
        labeled("Transport:", transportBox)
        labeled("Host:", hostField)
        labeled("Port:", portField)
        labeled("Bearer token:", JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
            isOpaque = false; add(tokenField)
            add(JButton("Generate").apply { addActionListener { tokenField.text = McpSettings.generateToken(); refreshConnect() } })
        })
        c.gridx = 1; c.gridy = row++; form.add(enableBox, c)
        c.gridx = 1; c.gridy = row++; form.add(unsafeBox, c)
        c.gridx = 1; c.gridy = row++; form.add(scopeBox, c)
        c.gridx = 1; c.gridy = row++
        form.add(JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply {
            isOpaque = false
            add(startButton); add(Box.createHorizontalStrut(6)); add(stopButton); add(Box.createHorizontalStrut(6))
            add(JButton("Save settings").apply { addActionListener { saveSettings(); refreshConnect() } })
        }, c)
        return form
    }

    // ---- Tools ----

    private fun toolsTab(): JPanel {
        val p = JPanel(BorderLayout())
        p.border = BorderFactory.createEmptyBorder(DesignTokens.S3, DesignTokens.S3, DesignTokens.S3, DesignTokens.S3)
        val top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0)).apply {
            add(JLabel("Search:")); add(toolSearch)
            add(JButton("Enable all").apply { addActionListener { setAllTools(true) } })
            add(JButton("Disable all").apply { addActionListener { setAllTools(false) } })
        }
        toolSearch.toolTipText = "Filter tools by id or category"
        toolSearch.addActionListener { rebuildToolRows() }
        p.add(top, BorderLayout.NORTH)
        p.add(JScrollPane(toolListPanel), BorderLayout.CENTER)
        p.add(JLabel("Toggle tools, then restart the server to apply. Pro-only tools need Burp Professional.").apply {
            foreground = DesignTokens.textMuted
            border = BorderFactory.createEmptyBorder(6, 2, 0, 0)
        }, BorderLayout.SOUTH)
        return p
    }

    private fun rebuildToolRows() {
        toolListPanel.removeAll()
        toolToggles.clear()
        val filter = toolSearch.text.trim().lowercase()
        val meta = supervisor.toolMetadata()
            .filter { filter.isEmpty() || it.id.lowercase().contains(filter) || it.category.lowercase().contains(filter) }
            .sortedWith(compareBy({ it.category }, { it.id }))
        var currentCategory: String? = null
        for (m in meta) {
            if (m.category != currentCategory) {
                currentCategory = m.category
                toolListPanel.add(JLabel(m.category).apply {
                    font = DesignTokens.baseFont.deriveFont(java.awt.Font.BOLD)
                    border = BorderFactory.createEmptyBorder(8, 2, 2, 0)
                })
            }
            val toggle = ToggleSwitch().apply { isSelected = store.current.toolToggles[m.id] ?: m.defaultEnabled }
            toggle.addActionListener { onToolToggle(m.id, toggle.isSelected) }
            toolToggles[m.id] = toggle
            val chips = buildString {
                if (m.proOnly) append("  [pro]")
                if (m.mutating) append("  [unsafe]")
            }
            val row = JPanel(FlowLayout(FlowLayout.LEFT, 8, 2)).apply {
                isOpaque = false
                add(toggle)
                add(JLabel(m.id))
                if (chips.isNotEmpty()) add(JLabel(chips).apply { foreground = DesignTokens.textMuted })
            }
            toolListPanel.add(row)
        }
        toolListPanel.revalidate()
        toolListPanel.repaint()
    }

    private fun onToolToggle(id: String, enabled: Boolean) {
        val next = store.current.toolToggles.toMutableMap().apply { this[id] = enabled }
        store.save(store.current.copy(toolToggles = next))
    }

    private fun setAllTools(enabled: Boolean) {
        val next = store.current.toolToggles.toMutableMap()
        supervisor.toolMetadata().forEach { next[it.id] = enabled }
        store.save(store.current.copy(toolToggles = next))
        rebuildToolRows()
    }

    // ---- Connect ----

    private fun connectTab(): JPanel {
        val p = JPanel(BorderLayout())
        p.border = BorderFactory.createEmptyBorder(DesignTokens.S4, DesignTokens.S4, DesignTokens.S4, DesignTokens.S4)
        p.add(JScrollPane(connectArea), BorderLayout.CENTER)
        p.add(JButton("Copy to clipboard").apply {
            addActionListener { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(connectArea.text), null) }
        }, BorderLayout.SOUTH)
        return p
    }

    private fun refreshConnect() {
        val s = store.current
        val path = when (s.transport) {
            TransportMode.STREAMABLE_HTTP -> "/mcp"
            TransportMode.SSE -> "/sse"
            TransportMode.STDIO -> ""
        }
        val url = "http://${s.host}:${s.port}$path"
        val authHeader = if (s.token.isNotEmpty()) " --header \"Authorization: Bearer ${s.token}\"" else ""
        connectArea.text = buildString {
            appendLine("# Endpoint")
            appendLine(url)
            appendLine()
            appendLine("# Claude Code (streamable-http)")
            appendLine("claude mcp add --transport http revolt-burp $url$authHeader")
            appendLine()
            appendLine("# Claude Desktop (via supergateway, for SSE)")
            appendLine("""{ "mcpServers": { "revolt-burp": { "command": "npx", "args": ["-y", "supergateway", "--sse", "http://${s.host}:${s.port}/sse"] } } }""")
            if (s.token.isNotEmpty()) {
                appendLine()
                appendLine("# Remember: external/non-loopback clients must send  Authorization: Bearer ${s.token}")
            }
        }
    }

    // ---- shared ----

    private fun onStart() {
        val settings = saveSettings()
        refreshConnect()
        Thread({ supervisor.start(settings) }, "revoltmcp-start").apply { isDaemon = true }.start()
    }

    private fun onStop() {
        Thread({ supervisor.stop() }, "revoltmcp-stop").apply { isDaemon = true }.start()
    }

    private fun saveSettings(): McpSettings {
        val settings = store.current.copy(
            enabled = enableBox.isSelected,
            transport = transportBox.selectedItem as TransportMode,
            host = hostField.text.trim().ifEmpty { "127.0.0.1" },
            port = portField.text.trim().toIntOrNull() ?: store.current.port,
            token = tokenField.text.trim(),
            scopeOnly = scopeBox.isSelected,
            unsafeToolsEnabled = unsafeBox.isSelected,
        )
        return store.save(settings)
    }

    private fun loadFromSettings(s: McpSettings) {
        transportBox.selectedItem = s.transport
        hostField.text = s.host
        portField.text = s.port.toString()
        tokenField.text = s.token
        enableBox.isSelected = s.enabled
        unsafeBox.isSelected = s.unsafeToolsEnabled
        scopeBox.isSelected = s.scopeOnly
    }

    private fun renderStatus(s: McpServerStatus) {
        val (label, color) = when (s.state) {
            McpServerState.RUNNING -> "RUNNING" to DesignTokens.success
            McpServerState.STARTING -> "STARTING…" to DesignTokens.warning
            McpServerState.STOPPED -> "STOPPED" to DesignTokens.textMuted
            McpServerState.ERROR -> "ERROR" to DesignTokens.error
        }
        headerBadge.set(label, color)
        headerBadge.toolTipText = s.lastError ?: s.boundUrl
        startButton.isEnabled = s.state != McpServerState.RUNNING && s.state != McpServerState.STARTING
        stopButton.isEnabled = s.state == McpServerState.RUNNING
        refreshDashboard()
    }
}
