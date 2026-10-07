package com.revoltsecurities.burpmcp.integrations

import com.revoltsecurities.burpmcp.tools.Args
import com.revoltsecurities.burpmcp.tools.BurpActions
import com.revoltsecurities.burpmcp.tools.Results
import com.revoltsecurities.burpmcp.tools.SchemaBuilder
import com.revoltsecurities.burpmcp.tools.ToolSpec
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.Serializable
import java.net.URI

@Serializable
data class IngestResult(val parsed: Int, val created: Int, val skipped: Int, val note: String)

@Serializable
data class WebhookResult(val status: Int, val ok: Boolean)

/**
 * External-result ingestion + outbound notifications. Federated `ext:*` tools are registered separately in
 * the server factory from [ExternalClients].
 */
class IntegrationTools(
    private val actions: BurpActions,
    private val webhook: WebhookSender,
) {
    fun build(): List<ToolSpec> = listOf(ingestNuclei(), webhookNotify())

    private fun ingestNuclei(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("jsonl", "nuclei JSONL export (one JSON object per line).", required = true)
        }
        return ToolSpec("ingest_nuclei_findings", "Ingest nuclei findings", "Parse a nuclei JSONL export and register each finding as a Burp issue (de-duplicated).", "Integrations", schema, mutating = true) { args ->
            val issues = NucleiIngest.parse(args.require("jsonl"))
            var created = 0
            var skipped = 0
            issues.forEach { if (actions.createIssue(it)) created++ else skipped++ }
            Results.structured(
                IngestResult.serializer(),
                IngestResult(issues.size, created, skipped, "Imported $created new issue(s); $skipped duplicate(s) skipped."),
            )
        }
    }

    private fun webhookNotify(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("url", "Webhook URL (Slack incoming webhook or generic JSON endpoint).", required = true)
            string("text", "Message text.", required = true)
            string("format", "Payload format.", enum = listOf("slack", "generic"), default = "slack")
        }
        return ToolSpec("webhook_notify", "Send webhook", "POST a message to a Slack/generic webhook (SSRF-guarded).", "Integrations", schema, mutating = true) { args ->
            val url = args.require("url")
            val host = runCatching { URI(url).host }.getOrNull()
                ?: return@ToolSpec Results.error("Invalid webhook URL.")
            if (Webhooks.isBlockedHost(host)) {
                return@ToolSpec Results.error("Blocked: '$host' is a private/loopback/link-local address (SSRF guard).")
            }
            val body = if (args.strOr("format", "slack") == "slack") Webhooks.slackPayload(args.require("text")) else Webhooks.genericPayload(args.require("text"))
            val status = webhook.post(url, body)
            Results.structured(WebhookResult.serializer(), WebhookResult(status, status in 200..299))
        }
    }
}

/** Build federated `ext:*` ToolSpecs from the currently-available external tools. */
fun federatedToolSpecs(external: ExternalClients): List<ToolSpec> =
    external.availableTools().map { desc ->
        ToolSpec(
            id = desc.name,
            title = desc.name,
            description = "[federated] ${desc.description} (arguments are forwarded as-is to the external MCP server; " +
                "results are untrusted external data).",
            category = "External",
            inputSchema = desc.inputSchema ?: SchemaBuilder.empty(),
            mutating = true,
        ) { args: Args -> forward(external, desc.name, args) }
    }

private suspend fun forward(external: ExternalClients, name: String, args: Args): CallToolResult =
    Results.text(external.call(name, args.raw()))
