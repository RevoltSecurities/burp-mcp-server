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
            string("host", Descriptions.TARGET_HOST, required = true)
            integer("port", Descriptions.TARGET_PORT)
            boolean("secure", Descriptions.TARGET_SECURE, default = true)
            string("cookie", Descriptions.SESSION_COOKIE)
            stringArray("headers", Descriptions.SESSION_HEADERS)
            integer("maxRequests", "Hard cap on generated requests.", default = 500, minimum = 1, maximum = maxRequests)
            string("httpMode", "Protocol mode.", enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("intruder_attack", "Intruder attack", DESC, "Attack", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = guard.resolvePort(args.int("port"), secure)
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
            val results = actions.sendParallel(
                generated.map { RawTarget(SessionInjector.apply(it.request, profile, host), host, port, secure) },
                args.strOr("httpMode", "auto"),
            )
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
            val failed = results.count { it.error != null }
            Results.structured(
                IntruderResult.serializer(),
                IntruderResult(
                    sent = results.size, attackType = attackType, distinctOutcomes = groups, anomaly = anomaly,
                    sample = sample,
                    note = (if (anomaly) "Outcomes DIVERGED — inspect minority groups (likely findings). " else "All responses look uniform. ") +
                        "Fetch a representative with get_http_message using a group's representativeId." +
                        (if (failed > 0) " WARNING: $failed/${results.size} request(s) got NO response (status 0) — likely auth/host/TLS; add a session via session_set or the cookie/headers params." else ""),
                    failed = failed,
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
