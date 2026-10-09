package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionProfile
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
    val failed: Int = 0,
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
    private val sessionProfile: () -> SessionProfile = { SessionProfile() },
    private val maxCount: Int = 50,
) {
    private val counter = AtomicInteger(0)

    private fun inject(args: Args, raw: String, host: String): String =
        SessionInjector.apply(raw, sessionProfile().mergedWith(SessionArgs.perCallOverride(args)), host)

    fun build(): List<ToolSpec> = listOf(parallelSend(), batchSend())

    private fun modeToHttp(mode: String): String = when (mode.lowercase()) {
        "single_packet", "single-packet" -> "http2"
        "last_byte", "last-byte" -> "http1"
        else -> "auto"
    }

    private fun isLastByte(mode: String): Boolean = mode.equals("last_byte", true) || mode.equals("last-byte", true)

    /** single_packet → Burp's HTTP/2 single-packet; last_byte → our clean-room HTTP/1 last-byte gate;
     *  parallel → ordinary concurrent HTTP/1 sends. */
    private fun fireRace(targets: List<RawTarget>, mode: String): List<SentExchange> =
        if (isLastByte(mode)) actions.sendLastByteSync(targets) else actions.sendParallel(targets, modeToHttp(mode))

    private fun transportLabel(mode: String): String = when {
        isLastByte(mode) -> "HTTP/1.1 last-byte sync"
        mode.lowercase().startsWith("single") -> "HTTP/2 single-packet"
        else -> modeToHttp(mode)
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
            string("raw_request", "The complete, BYTE-EXACT raw HTTP request to fire N times simultaneously. " + Descriptions.RAW_REQUEST_BYTE_EXACT, required = true)
            string("host", Descriptions.TARGET_HOST_OPT)
            integer("port", Descriptions.TARGET_PORT_OPT)
            boolean("secure", "Use TLS. " + Descriptions.TARGET_SECURE_OPT, default = true)
            integer("count", "How many copies to fire simultaneously.", default = 20, minimum = 2, maximum = maxCount)
            string("cookie", Descriptions.SESSION_COOKIE)
            stringArray("headers", Descriptions.SESSION_HEADERS)
            string("mode", "Synchronization mode.", enum = listOf("single_packet", "last_byte", "parallel"), default = "single_packet")
        }
        return ToolSpec("race_parallel_send", "Race: parallel send", DESC_PARALLEL, "Race", schema, mutating = true) { args ->
            val content = args.require("raw_request")
            val t = TargetArgs.resolve(args, content) ?: return@ToolSpec Results.error(Descriptions.NO_TARGET_HOST)
            scopeReject(baseUrl(t.host, t.port, t.secure))?.let { return@ToolSpec it }
            val count = args.intOr("count", 20).coerceIn(2, maxCount)
            val mode = args.strOr("mode", "single_packet")
            val target = RawTarget(inject(args, content, t.host), t.host, t.port, t.secure)
            val results = fireRace(List(count) { target }, mode)
            summarize(results, mode, "Fired $count identical requests (${transportLabel(mode)}).")
        }
    }

    private fun batchSend(): ToolSpec {
        val schema = SchemaBuilder.build {
            stringArray("raw_requests", "Two or more complete, BYTE-EXACT raw HTTP requests to fire together as one batch. " + Descriptions.RAW_REQUEST_BYTE_EXACT, required = true)
            string("host", "Target host shared by all requests. " + Descriptions.TARGET_HOST_OPT + " (derived from the first request).")
            integer("port", Descriptions.TARGET_PORT_OPT)
            boolean("secure", "Use TLS. " + Descriptions.TARGET_SECURE_OPT, default = true)
            string("cookie", Descriptions.SESSION_COOKIE)
            stringArray("headers", Descriptions.SESSION_HEADERS)
            string("mode", "Synchronization mode.", enum = listOf("single_packet", "last_byte", "parallel"), default = "single_packet")
        }
        return ToolSpec("race_batch_send", "Race: batch send", DESC_BATCH, "Race", schema, mutating = true) { args ->
            val raws = args.strList("raw_requests")
            if (raws.size < 2) return@ToolSpec Results.error("Provide at least two requests in 'raw_requests'.")
            val t = TargetArgs.resolve(args, raws.first()) ?: return@ToolSpec Results.error(Descriptions.NO_TARGET_HOST)
            scopeReject(baseUrl(t.host, t.port, t.secure))?.let { return@ToolSpec it }
            val mode = args.strOr("mode", "single_packet")
            val results = fireRace(raws.map { RawTarget(inject(args, it, t.host), t.host, t.port, t.secure) }, mode)
            summarize(results, mode, "Fired ${raws.size} distinct requests as one batch (${transportLabel(mode)}).")
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
        // Count degenerate (status 0 / no response) results, not just error!=null — a failed HTTP/2
        // negotiation (what single_packet uses) surfaces as status 0 with error==null.
        val failed = HttpSend.degenerateCount(results)
        val allFailed = HttpSend.allDegenerate(results)
        val edge = results.firstOrNull { HttpSend.edgeSignature(it) != null }?.let { HttpSend.edgeSignature(it) }
        val note = buildString {
            append(prefix)
            if (allFailed) {
                append(" ALL ${results.size} requests failed at the transport (status 0 / no response). ")
                if (modeToHttp(mode) == "http2") append("single_packet runs over HTTP/2, which this target's Burp connection could not negotiate — retry with mode=parallel or last_byte (HTTP/1.1), at reduced timing precision. ")
                else append("Check auth/host/TLS, or retry with a session via session_set. ")
                if (edge != null) append("The edge responded as '$edge' (likely a WAF/edge block). ")
            } else {
                append(if (anomaly) " Outcomes DIVERGED (${groups.size} groups) — possible race win; inspect the minority group via get_http_message." else " All responses identical.")
                if (failed > 0) append(" $failed/${results.size} request(s) got NO response (status 0) — likely auth/host/TLS; add a session via session_set or the cookie/headers params.")
                if (edge != null) append(" Some responses came from an edge/WAF layer (server=$edge).")
            }
        }
        return Results.structured(
            RaceResult.serializer(),
            RaceResult(results.size, mode, actions.managedEngineAvailable(), groups, anomaly, note, failed),
        )
    }

    companion object {
        private const val DESC_PARALLEL =
            "Fire N identical requests simultaneously to test for race conditions (single-packet over HTTP/2, " +
                "or last-byte sync over HTTP/1). Returns responses grouped by outcome; a divergent group is a likely " +
                "race win. Raw requests are sent byte-exact when no session profile is set (so smuggling/desync " +
                "payloads are preserved); setting a session profile or cookie/headers rewrites the request head."
        private const val DESC_BATCH =
            "Fire a group of DIFFERENT requests together as one batch (race/connection-level). Returns grouped " +
                "outcomes. Byte-exact with no session set; a session profile or cookie/headers rewrites the head."
    }
}
