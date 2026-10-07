package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.MessageRegistry
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.Serializable
import java.util.concurrent.atomic.AtomicInteger

@Serializable
data class RaceResult(
    val sent: Int,
    val mode: String,
    val managedEngineAvailable: Boolean,
    val distinctOutcomes: List<OutcomeGroup>,
    val anomaly: Boolean,
    val note: String,
)

/**
 * Race-condition / high-throughput tools. Built on `sendRequests` (available on all Burp versions);
 * HTTP/2 mode lets Burp coalesce into a single packet (best-effort — see docs/research/09). Output is
 * grouped by outcome so a 30-request run stays a few lines; a representative response per group is
 * registered for get_http_message. Mutating → unsafe-gated; scope-checked before building any request.
 */
class RaceTools(
    private val actions: BurpActions,
    private val registry: MessageRegistry,
    private val scopeOnly: () -> Boolean,
    private val isInScope: (String) -> Boolean,
    private val maxCount: Int = 50,
) {
    private val counter = AtomicInteger(0)

    fun build(): List<ToolSpec> = listOf(parallelSend(), batchSend())

    private fun modeToHttp(mode: String): String = when (mode.lowercase()) {
        "single_packet", "single-packet" -> "http2"
        "last_byte", "last-byte" -> "http1"
        else -> "auto"
    }

    private fun baseUrl(host: String, port: Int, secure: Boolean): String {
        val scheme = if (secure) "https" else "http"
        val portPart = if ((secure && port == 443) || (!secure && port == 80)) "" else ":$port"
        return "$scheme://$host$portPart/"
    }

    private fun scopeReject(url: String): CallToolResult? =
        if (scopeOnly() && !isInScope(url)) Results.error("Blocked: $url is out of scope and scope-confinement is enabled.") else null

    private fun parallelSend(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", "The raw HTTP request to fire N times simultaneously. " + Descriptions.RAW_REQUEST, required = true)
            string("host", Descriptions.TARGET_HOST, required = true)
            integer("port", "Target port (default 443 if secure else 80).")
            boolean("secure", "Use TLS.", default = true)
            integer("count", "How many copies to fire simultaneously.", default = 20, minimum = 2, maximum = maxCount)
            string("mode", "Synchronization mode.", enum = listOf("single_packet", "last_byte", "parallel"), default = "single_packet")
        }
        return ToolSpec("race_parallel_send", "Race: parallel send", DESC_PARALLEL, "Race", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = args.int("port") ?: if (secure) 443 else 80
            scopeReject(baseUrl(host, port, secure))?.let { return@ToolSpec it }
            val count = args.intOr("count", 20).coerceIn(2, maxCount)
            val mode = args.strOr("mode", "single_packet")
            val target = RawTarget(args.require("content"), host, port, secure)
            val results = actions.sendParallel(List(count) { target }, modeToHttp(mode))
            summarize(results, mode, "Fired $count identical requests (${modeToHttp(mode)}).")
        }
    }

    private fun batchSend(): ToolSpec {
        val schema = SchemaBuilder.build {
            stringArray("requests", "Two or more raw HTTP requests (each a full raw request per http_send format) to fire together as one batch.", required = true)
            string("host", "Target host shared by all requests. " + Descriptions.TARGET_HOST, required = true)
            integer("port", "Target port (default 443 if secure else 80).")
            boolean("secure", "Use TLS.", default = true)
            string("mode", "Synchronization mode.", enum = listOf("single_packet", "last_byte", "parallel"), default = "single_packet")
        }
        return ToolSpec("race_batch_send", "Race: batch send", DESC_BATCH, "Race", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = args.int("port") ?: if (secure) 443 else 80
            scopeReject(baseUrl(host, port, secure))?.let { return@ToolSpec it }
            val raws = args.strList("requests")
            if (raws.size < 2) return@ToolSpec Results.error("Provide at least two requests in 'requests'.")
            val mode = args.strOr("mode", "single_packet")
            val results = actions.sendParallel(raws.map { RawTarget(it, host, port, secure) }, modeToHttp(mode))
            summarize(results, mode, "Fired ${raws.size} distinct requests as one batch (${modeToHttp(mode)}).")
        }
    }

    private fun summarize(results: List<SentExchange>, mode: String, prefix: String): CallToolResult {
        val groups = RaceAnalyzer.analyze(results).map { g ->
            val ex = results.getOrNull(g.exampleIndex)
            if (ex == null) {
                g
            } else {
                val id = "race:${counter.incrementAndGet()}"
                registry.put(MessageRegistry.Handle(id, ex.mimeType, { ex.requestBytes }, { ex.responseBytes }))
                g.copy(representativeId = id)
            }
        }
        val anomaly = RaceAnalyzer.isAnomalous(groups)
        val note = buildString {
            append(prefix)
            append(if (anomaly) " Outcomes DIVERGED (${groups.size} groups) — possible race win; inspect the minority group via get_http_message." else " All responses identical.")
        }
        return Results.structured(
            RaceResult.serializer(),
            RaceResult(results.size, mode, actions.managedEngineAvailable(), groups, anomaly, note),
        )
    }

    companion object {
        private const val DESC_PARALLEL =
            "Fire N identical requests simultaneously to test for race conditions (single-packet over HTTP/2, " +
                "or last-byte sync over HTTP/1). Returns responses grouped by outcome; a divergent group is a likely race win."
        private const val DESC_BATCH =
            "Fire a group of DIFFERENT requests together as one batch (race/connection-level). Returns grouped outcomes."
    }
}
