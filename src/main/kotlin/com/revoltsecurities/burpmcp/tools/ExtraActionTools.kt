package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

@Serializable
data class OrganizerItemsResult(val items: List<OrganizerItemDTO>)

/** Organizer, WebSocket send, and BCheck/Bambda import tools. */
class ExtraActionTools(
    private val actions: BurpActions,
    private val guard: ScopeGuard,
) {
    fun build(): List<ToolSpec> = listOf(
        organizerSend(), organizerItems(), wsSend(), bcheckImport(), bambdaImport(),
    )

    private fun organizerSend(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", Descriptions.RAW_REQUEST, required = true)
            string("host", Descriptions.TARGET_HOST, required = true)
            integer("port", Descriptions.TARGET_PORT)
            boolean("secure", Descriptions.TARGET_SECURE, default = true)
        }
        return ToolSpec("organizer_send", "Send to Organizer", "Store a request in Burp's Organizer for later.", "Organizer", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = guard.resolvePort(args.int("port"), secure)
            guard.reject(host, port, secure)?.let { return@ToolSpec it }
            actions.sendToOrganizer(args.require("content"), host, port, secure)
            Results.text("Stored in Organizer ($host:$port).")
        }
    }

    private fun organizerItems(): ToolSpec =
        ToolSpec("organizer_items", "List Organizer items", "List items stored in Burp's Organizer.", "Organizer", SchemaBuilder.empty()) {
            Results.structured(OrganizerItemsResult.serializer(), OrganizerItemsResult(actions.organizerItems()))
        }

    private fun wsSend(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("host", Descriptions.TARGET_HOST, required = true)
            string("path", "WebSocket upgrade path, e.g. \"/ws\".", default = "/")
            boolean("secure", "Use wss/TLS.", default = true)
            string("message", "Text message to send after the socket opens.", required = true)
            integer("waitMs", "How long to collect replies before closing (ms, max 10000).", default = 1500, minimum = 0, maximum = 10_000)
        }
        return ToolSpec("ws_send", "WebSocket send", "Open a WebSocket, send a text message, collect replies for a window, then close.", "WebSocket", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true)
            guard.reject(host, if (secure) 443 else 80, secure)?.let { return@ToolSpec it }
            val result = actions.wsSend(host, args.strOr("path", "/"), secure, args.require("message"), args.intOr("waitMs", 1500).toLong())
            Results.structured(WsSendResult.serializer(), result)
        }
    }

    private fun bcheckImport(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("script", "The BCheck script source to import.", required = true)
            boolean("enabled", "Enable the BCheck after import.", default = true)
        }
        return ToolSpec("bcheck_import", "Import BCheck", "Import a BCheck into Burp (runs within subsequent audits).", "Scanner", schema, mutating = true, proOnly = true) { args ->
            Results.structured(ImportOutcome.serializer(), actions.importBCheck(args.require("script"), args.boolOr("enabled", true)))
        }
    }

    private fun bambdaImport(): ToolSpec {
        val schema = SchemaBuilder.build { string("script", "The Bambda script source to import.", required = true) }
        return ToolSpec("bambda_import", "Import Bambda", "Import a Bambda (custom filter/match-replace) into Burp's library.", "Config", schema, mutating = true) { args ->
            Results.structured(ImportOutcome.serializer(), actions.importBambda(args.require("script")))
        }
    }
}
