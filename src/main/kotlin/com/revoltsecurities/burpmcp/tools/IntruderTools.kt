package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionProfile
import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import java.util.concurrent.atomic.AtomicInteger

@Serializable
data class IntruderHit(val index: Int, val payloads: List<String>, val status: Int?, val length: Int)

@Serializable
data class IntruderResult(
    val sent: Int,
    val attackType: String,
    val distinctOutcomes: List<OutcomeGroup>,
    val anomaly: Boolean,
    val sample: List<IntruderHit>,
    val note: String,
    val failed: Int = 0,
    val httpModeUsed: String? = null,
)

/**
 * Programmatic Intruder (`intruder_attack`). Burp's own Intruder can't be *run* via Montoya (send-only), so
 * this generates the requests from payload positions (sniper/pitchfork/clusterbomb) and fires them via
 * `sendRequests`, then returns grouped-outcome analysis + a compact per-payload sample. Mutating, scope-gated.
 */
class IntruderTools(
    private val actions: BurpActions,
    private val registry: MessageRegistry,
    private val guard: ScopeGuard,
    private val wordlistsDir: () -> String = { "" },
    private val sessionProfile: () -> SessionProfile = { SessionProfile() },
    private val maxRequests: Int = 2_000,
    private val sampleSize: Int = 25,
) {
    private val counter = AtomicInteger(0)

    fun build(): List<ToolSpec> = listOf(attack(), listWordlists())

    private fun listWordlists(): ToolSpec =
        ToolSpec("list_wordlists", "List wordlists", "List user-configured payload wordlists (by filename) available to intruder_attack via payloadFile/payloadFiles.", "Attack", SchemaBuilder.empty()) {
            val base = Wordlists.baseDir(wordlistsDir())
            Results.structured(WordlistsResult.serializer(), WordlistsResult(base.toAbsolutePath().toString(), Wordlists.list(base)))
        }

    private fun attack(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("template", "Raw HTTP request with §…§ markers around each insertion position (text between the " +
                "markers is the base value). " + Descriptions.RAW_REQUEST, required = true)
            string("attackType", "sniper = 1 payload list, fuzz one position at a time; pitchfork = one list per " +
                "position in lockstep; clusterbomb = one list per position, all combinations.",
                enum = listOf("sniper", "pitchfork", "clusterbomb"), default = "sniper")
            stringArray("payloads", "Inline payload list for SNIPER (string array).")
            string("payloadFile", "SNIPER: filename of a user-configured wordlist to use as payloads (discover names with list_wordlists). Combined with any inline 'payloads'.")
            stringArray("payloadFiles", "PITCHFORK/CLUSTERBOMB: wordlist filenames, one per position in order; appended after any inline payloadSets.")
            // payloadSets (array of string arrays) is read from raw args for pitchfork/clusterbomb.
            string("host", Descriptions.TARGET_HOST_OPT + " (derived from the template's Host header).")
            integer("port", Descriptions.TARGET_PORT_OPT)
            boolean("secure", Descriptions.TARGET_SECURE_OPT, default = true)
            string("cookie", Descriptions.SESSION_COOKIE)
            stringArray("headers", Descriptions.SESSION_HEADERS)
            integer("maxRequests", "Hard cap on generated requests.", default = 500, minimum = 1, maximum = maxRequests)
            string("httpMode", Descriptions.HTTP_MODE, enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
            integer("concurrency", "Max simultaneous in-flight requests. >0 routes the attack through Burp's managed request engine (concurrency-limited, retried) when available — recommended for large or rate-sensitive targets; 0 = fire the whole batch at once.", default = 0, minimum = 0)
            integer("throttleMs", "Delay between requests in milliseconds (engine throttle). >0 also uses the managed engine. 0 = no throttle.", default = 0, minimum = 0)
            integer("maxRetries", "Managed-engine retries per failed request (only applies when concurrency/throttleMs route through the engine).", default = 0, minimum = 0)
        }
        return ToolSpec("intruder_attack", "Intruder attack", DESC, "Attack", schema, mutating = true) { args ->
            // Derive host from the template with §…§ markers stripped, so a marker in the Host header
            // (fuzzing the Host) doesn't become the routing/scope host.
            val t = TargetArgs.resolve(args, args.str("template")?.replace("§", ""))
                ?: return@ToolSpec Results.error(Descriptions.NO_TARGET_HOST)
            val host = t.host; val port = t.port; val secure = t.secure
            guard.reject(host, port, secure)?.let { return@ToolSpec it }

            val attackType = args.strOr("attackType", "sniper")
            val cap = args.intOr("maxRequests", 500).coerceIn(1, maxRequests)
            val base = Wordlists.baseDir(wordlistsDir())
            val sets = if (attackType == "sniper") {
                listOf(args.strList("payloads") + (args.str("payloadFile")?.let { Wordlists.read(it, base) } ?: emptyList()))
            } else {
                payloadSets(args) + args.strList("payloadFiles").map { Wordlists.read(it, base) }
            }
            if (sets.isEmpty() || sets.all { it.isEmpty() }) {
                return@ToolSpec Results.error("No payloads provided. Use 'payloads'/'payloadFile' for sniper, or 'payloadSets'/'payloadFiles' for pitchfork/clusterbomb. Discover files with list_wordlists.")
            }

            val generated = PayloadEngine.generate(args.require("template"), attackType, sets, cap)
            if (generated.isEmpty()) {
                return@ToolSpec Results.error("No requests generated. Check that the template contains §…§ markers and payloads are non-empty.")
            }

            val profile = sessionProfile().mergedWith(SessionArgs.perCallOverride(args))
            val targets = generated.map { RawTarget(SessionInjector.apply(it.request, profile, host), host, port, secure) }
            // Pick a working transport before firing the whole batch: probe with the first generated request so
            // an `auto` run on a target whose HTTP/2 Burp can't negotiate falls back to http1 instead of
            // returning an all-status-0 batch (which used to report failed=0 and look "uniform").
            val requestedMode = args.strOr("httpMode", "auto")
            val sel = HttpSend.select(requestedMode) { m ->
                actions.sendParallel(listOf(targets.first()), m).firstOrNull()
                    ?: SentExchange(null, null, ByteArray(0), null, "no response")
            }
            // Route through Burp's managed engine (concurrency-limited/throttled/retried) when the caller asked
            // for it AND the working transport is plain `auto` (the engine negotiates like auto and takes no
            // mode); otherwise fire the proven parallel batch in the probed mode.
            val concurrency = args.intOr("concurrency", 0)
            val throttleMs = args.intOr("throttleMs", 0)
            val useEngine = (concurrency > 0 || throttleMs > 0) && sel.mode.equals("auto", ignoreCase = true)
            val engineUsed = useEngine && actions.managedEngineAvailable()
            val results = if (useEngine) {
                actions.sendManaged(targets, concurrency, throttleMs.toLong(), args.intOr("maxRetries", 0))
            } else {
                actions.sendParallel(targets, sel.mode)
            }
            val groups = RaceAnalyzer.analyze(results).map { g ->
                val ex = results.getOrNull(g.exampleIndex) ?: return@map g
                val id = "intr:${counter.incrementAndGet()}"
                registry.put(MessageRegistry.Handle(id, ex.mimeType, { ex.requestBytes }, { ex.responseBytes }))
                g.copy(representativeId = id)
            }
            val hits = results.mapIndexed { i, ex ->
                IntruderHit(i, generated.getOrNull(i)?.payloads ?: emptyList(), ex.statusCode, ex.responseBytes?.size ?: 0)
            }
            // sample: smallest outcome groups first (anomalies), so a race/auth-bypass win surfaces.
            val sizeByKey = hits.groupingBy { it.status to it.length }.eachCount()
            val sample = hits.sortedBy { sizeByKey[it.status to it.length] ?: 0 }.take(sampleSize)
            val anomaly = RaceAnalyzer.isAnomalous(groups)
            // Count every degenerate result (status 0 / no response), not only error!=null — a failed HTTP/2
            // negotiation surfaces as status 0 with error==null, which the old count missed entirely.
            val failed = HttpSend.degenerateCount(results)
            val allFailed = HttpSend.allDegenerate(results)
            val edge = results.firstOrNull { HttpSend.edgeSignature(it) != null }?.let { HttpSend.edgeSignature(it) }
            val note = buildString {
                if (allFailed) {
                    append("ALL ${results.size} requests failed at the transport (status 0 / no response) — no useful data. ")
                    append(HttpSend.transportFailureNote(sel.tried, edge))
                } else {
                    append(if (anomaly) "Outcomes DIVERGED — inspect minority groups (likely findings). " else "All responses look uniform. ")
                    append("Fetch a representative with get_http_message using a group's representativeId.")
                    if (engineUsed) append(" Sent via Burp's managed request engine (concurrency=$concurrency, throttleMs=$throttleMs).")
                    else if (useEngine) append(" (Managed engine requested but unavailable on this Burp; used a parallel batch.)")
                    if (sel.switchedFrom(requestedMode)) append(" (Auto-selected httpMode=${sel.mode}.)")
                    if (failed > 0) append(" WARNING: $failed/${results.size} request(s) got NO response (status 0) — likely auth/host/TLS; add a session via session_set or the cookie/headers params.")
                    if (edge != null) append(" Some responses came from an edge/WAF layer (server=$edge).")
                }
            }
            Results.structured(
                IntruderResult.serializer(),
                IntruderResult(
                    sent = results.size, attackType = attackType, distinctOutcomes = groups, anomaly = anomaly,
                    sample = sample, note = note, failed = failed, httpModeUsed = sel.mode,
                ),
            )
        }
    }

    private fun payloadSets(args: Args): List<List<String>> {
        val arr = args.raw()["payloadSets"] as? JsonArray ?: return emptyList()
        return arr.mapNotNull { inner ->
            (inner as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.let { p -> if (p.isString) p.content else null } }
        }
    }

    companion object {
        private const val DESC =
            "Run a programmatic Intruder-style attack: substitute payloads at §…§ positions (sniper/pitchfork/" +
                "clusterbomb), fire all requests, and return grouped outcomes + a per-payload sample. Divergent " +
                "groups are likely findings; fetch evidence via get_http_message. Scope-gated and capped."
    }
}
