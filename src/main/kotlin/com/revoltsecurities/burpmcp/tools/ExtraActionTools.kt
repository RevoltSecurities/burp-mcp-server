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
        organizerSend(), organizerItems(), wsSend(), bcheckImport(),
    )

    private fun organizerSend(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("host", Descriptions.TARGET_HOST_OPT)
            integer("port", Descriptions.TARGET_PORT_OPT)
            boolean("secure", Descriptions.TARGET_SECURE_OPT, default = true)
            structuredRequestParams()
        }
        return ToolSpec("organizer_send", "Send to Organizer", "Store a request in Burp's Organizer for later.", "Organizer", schema, mutating = true) { args ->
            val r = RequestBuilder.fromArgs(args)
            val t = TargetArgs.Target(r.host, r.port, r.secure)
            guard.reject(t.host, t.port, t.secure)?.let { return@ToolSpec it }
            actions.sendToOrganizer(r.raw, t.host, t.port, t.secure)
            Results.text("Stored in Organizer (${t.host}:${t.port}).")
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
            string("script", BCHECK_SCRIPT, required = true)
            boolean("enabled", "Enable the BCheck after import.", default = true)
        }
        return ToolSpec("bcheck_import", "Import BCheck", BCHECK_DESC, "Scanner", schema, mutating = true, proOnly = true) { args ->
            val outcome = actions.importBCheck(args.require("script"), args.boolOr("enabled", true))
            // Burp reports LOADED_WITH_ERRORS (not a failure status) for broken scripts — surface that as an error.
            if (outcome.ok) Results.structured(ImportOutcome.serializer(), outcome)
            else Results.structuredError(ImportOutcome.serializer(), outcome)
        }
    }

    companion object {
        private const val BCHECK_DESC =
            "Import a BCheck (Burp's custom scan-check DSL) so it runs within subsequent audits. Returns ok=false " +
                "with the parser messages in `errors` when the script has syntax/semantic problems (Burp loads it as " +
                "LOADED_WITH_ERRORS rather than rejecting it, so always check ok/errors)."
        private const val BCHECK_SCRIPT =
            "The BCheck script source. BCheck is a small declarative DSL, NOT free text. Minimal shape:\n" +
                "  metadata:\n" +
                "    language: v2-beta\n" +
                "    name: \"My check\"\n" +
                "    description: \"...\"\n" +
                "    author: \"...\"\n" +
                "  given request then\n" +
                "    send request called check:\n" +
                "      replacing path: \"/probe\"\n" +
                "    if {check.response.status_code} is \"200\" then\n" +
                "      report issue:\n" +
                "        severity: info\n" +
                "        confidence: tentative\n" +
                "        detail: \"found\"\n" +
                "    end if\n" +
                "Use `language: v2-beta` (v1-beta is outdated). Keys are indented YAML-like blocks. If import returns " +
                "errors, fix the reported lines; see PortSwigger's BCheck reference for the full grammar."
    }
}
