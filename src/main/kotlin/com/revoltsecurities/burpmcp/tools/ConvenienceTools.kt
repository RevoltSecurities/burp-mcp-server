package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionProfile
import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.serialization.Serializable
import java.util.concurrent.atomic.AtomicInteger

@Serializable
data class SendAnalyzeResult(
    val id: String,
    val ok: Boolean,
    val status: Int?,
    val statusText: String,
    val mimeType: String? = null,
    val responseLength: Int,
    val reflected: List<ReflectedParam>,
    val response: ParsedResponse,
    val note: String,
    val error: String? = null,
)

@Serializable
data class SendCompareResult(
    val idA: String,
    val idB: String,
    val ok: Boolean,
    val statusA: Int?,
    val statusB: Int?,
    val statusTextA: String,
    val statusTextB: String,
    val lengthA: Int,
    val lengthB: Int,
    val diff: String,
    val reflectedA: List<ReflectedParam>,
    val reflectedB: List<ReflectedParam>,
    val errorA: String? = null,
    val errorB: String? = null,
    val note: String? = null,
)

/** Repeater-style one-call send-and-analyze helpers (mutating, scope-gated). */
class ConvenienceTools(
    private val actions: BurpActions,
    private val registry: MessageRegistry,
    private val guard: ScopeGuard,
    private val sessionProfile: () -> SessionProfile = { SessionProfile() },
) {
    private val counter = AtomicInteger(0)

    private fun inject(args: Args, raw: String, host: String): String =
        SessionInjector.apply(raw, sessionProfile().mergedWith(SessionArgs.perCallOverride(args)), host)

    fun build(): List<ToolSpec> = listOf(sendAnalyze(), sendCompare())

    private fun register(prefix: String, ex: SentExchange): String {
        val id = "$prefix:${counter.incrementAndGet()}"
        registry.put(MessageRegistry.Handle(id, ex.mimeType, { ex.requestBytes }, { ex.responseBytes }))
        return id
    }

    private fun sendAnalyze(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("content", Descriptions.RAW_REQUEST, required = true)
            string("host", Descriptions.TARGET_HOST_OPT)
            integer("port", Descriptions.TARGET_PORT_OPT)
            boolean("secure", Descriptions.TARGET_SECURE_OPT, default = true)
            string("cookie", Descriptions.SESSION_COOKIE)
            stringArray("headers", Descriptions.SESSION_HEADERS)
            string("httpMode", "Protocol mode.", enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send_analyze", "Send + analyze", DESC_ANALYZE, "Requests", schema, mutating = true) { args ->
            val raw = args.require("content")
            val t = TargetArgs.resolve(args, raw) ?: return@ToolSpec Results.error(Descriptions.NO_TARGET_HOST)
            guard.reject(t.host, t.port, t.secure)?.let { return@ToolSpec it }
            val content = inject(args, raw, t.host)
            val ex = actions.sendRequest(content, t.host, t.port, t.secure, args.strOr("httpMode", "auto"))
            val respText = ex.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val id = register("ana", ex)
            val result = SendAnalyzeResult(
                id = id, ok = ex.error == null, status = ex.statusCode, statusText = ex.statusCode?.toString() ?: "no response",
                mimeType = ex.mimeType, responseLength = ex.responseBytes?.size ?: 0,
                reflected = HttpParse.findReflected(content, respText),
                response = HttpParse.parseResponse(respText, includeBody = false),
                note = ex.error?.let { "No HTTP response received: $it (status is unavailable, not 0)." }
                    ?: "Full response: get_http_message id=$id part=response section=body.",
                error = ex.error,
            )
            if (result.ok) Results.structured(SendAnalyzeResult.serializer(), result) else Results.structuredError(SendAnalyzeResult.serializer(), result)
        }
    }

    private fun sendCompare(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("contentA", "First raw HTTP request. " + Descriptions.RAW_REQUEST, required = true)
            string("contentB", "Second raw HTTP request to compare against A. " + Descriptions.RAW_REQUEST, required = true)
            string("host", Descriptions.TARGET_HOST_OPT + " (derived from contentA's Host header).")
            integer("port", Descriptions.TARGET_PORT_OPT)
            boolean("secure", Descriptions.TARGET_SECURE_OPT, default = true)
            string("cookie", Descriptions.SESSION_COOKIE)
            stringArray("headers", Descriptions.SESSION_HEADERS)
            string("httpMode", "Protocol mode.", enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send_compare", "Send + compare", DESC_COMPARE, "Requests", schema, mutating = true) { args ->
            val rawA = args.require("contentA"); val rawB = args.require("contentB")
            val t = TargetArgs.resolve(args, rawA) ?: return@ToolSpec Results.error(Descriptions.NO_TARGET_HOST)
            guard.reject(t.host, t.port, t.secure)?.let { return@ToolSpec it }
            val mode = args.strOr("httpMode", "auto")
            val a = inject(args, rawA, t.host); val b = inject(args, rawB, t.host)
            val exA = actions.sendRequest(a, t.host, t.port, t.secure, mode)
            val exB = actions.sendRequest(b, t.host, t.port, t.secure, mode)
            val respA = exA.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val respB = exB.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val ok = exA.error == null && exB.error == null
            val note = when {
                !ok -> "One or both requests got NO HTTP response (their status/length are unavailable, shown as 0). See errorA/errorB — add auth with session_set/cookie/headers, or check host/port/Host."
                exA.statusCode == exB.statusCode && respA == respB ->
                    "Responses are identical (same status, same bytes)."
                else -> "Responses differ — inspect diff, statuses and lengths."
            }
            val result = SendCompareResult(
                idA = register("cmp", exA), idB = register("cmp", exB), ok = ok,
                statusA = exA.statusCode, statusB = exB.statusCode,
                statusTextA = exA.statusCode?.toString() ?: "no response", statusTextB = exB.statusCode?.toString() ?: "no response",
                lengthA = exA.responseBytes?.size ?: 0, lengthB = exB.responseBytes?.size ?: 0,
                diff = HttpParse.diff(respA, respB),
                reflectedA = HttpParse.findReflected(a, respA), reflectedB = HttpParse.findReflected(b, respB),
                errorA = exA.error, errorB = exB.error, note = note,
            )
            if (ok) Results.structured(SendCompareResult.serializer(), result) else Results.structuredError(SendCompareResult.serializer(), result)
        }
    }

    companion object {
        private const val DESC_ANALYZE =
            "Send a raw HTTP request and get back, in ONE call: status (+ statusText), a parsed response, " +
                "reflected-parameter analysis, and a handle id to fetch the full body with get_http_message. " +
                "ok=false / statusText=\"no response\" (an MCP error) means the server sent nothing back — not a 0 code."
        private const val DESC_COMPARE =
            "Send two request variants to the same target and return their statuses/lengths (+ statusTextA/B), a line " +
                "diff of the responses, and reflected params for each — one-call differential testing. ok=false / " +
                "statusText \"no response\" means that side got no response (MCP error) — not a 0 status code."
    }
}
