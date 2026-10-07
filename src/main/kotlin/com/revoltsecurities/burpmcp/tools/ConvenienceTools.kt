package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.config.SessionProfile
import com.revoltsecurities.burpmcp.output.MessageRegistry
import kotlinx.serialization.Serializable
import java.util.concurrent.atomic.AtomicInteger

@Serializable
data class SendAnalyzeResult(
    val id: String,
    val status: Int?,
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
    val statusA: Int?,
    val statusB: Int?,
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
            string("host", Descriptions.TARGET_HOST, required = true)
            integer("port", Descriptions.TARGET_PORT)
            boolean("secure", Descriptions.TARGET_SECURE, default = true)
            string("cookie", Descriptions.SESSION_COOKIE)
            stringArray("headers", Descriptions.SESSION_HEADERS)
            string("httpMode", "Protocol mode.", enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send_analyze", "Send + analyze", DESC_ANALYZE, "Requests", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = guard.resolvePort(args.int("port"), secure)
            guard.reject(host, port, secure)?.let { return@ToolSpec it }
            val content = inject(args, args.require("content"), host)
            val ex = actions.sendRequest(content, host, port, secure, args.strOr("httpMode", "auto"))
            val respText = ex.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val id = register("ana", ex)
            Results.structured(
                SendAnalyzeResult.serializer(),
                SendAnalyzeResult(
                    id = id, status = ex.statusCode, mimeType = ex.mimeType, responseLength = ex.responseBytes?.size ?: 0,
                    reflected = HttpParse.findReflected(content, respText),
                    response = HttpParse.parseResponse(respText, includeBody = false),
                    note = ex.error?.let { "Request failed: $it" } ?: "Full response: get_http_message id=$id part=response section=body.",
                    error = ex.error,
                ),
            )
        }
    }

    private fun sendCompare(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("contentA", "First raw HTTP request. " + Descriptions.RAW_REQUEST, required = true)
            string("contentB", "Second raw HTTP request to compare against A. " + Descriptions.RAW_REQUEST, required = true)
            string("host", Descriptions.TARGET_HOST, required = true)
            integer("port", Descriptions.TARGET_PORT)
            boolean("secure", Descriptions.TARGET_SECURE, default = true)
            string("cookie", Descriptions.SESSION_COOKIE)
            stringArray("headers", Descriptions.SESSION_HEADERS)
            string("httpMode", "Protocol mode.", enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send_compare", "Send + compare", DESC_COMPARE, "Requests", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = guard.resolvePort(args.int("port"), secure)
            guard.reject(host, port, secure)?.let { return@ToolSpec it }
            val mode = args.strOr("httpMode", "auto")
            val a = inject(args, args.require("contentA"), host); val b = inject(args, args.require("contentB"), host)
            val exA = actions.sendRequest(a, host, port, secure, mode)
            val exB = actions.sendRequest(b, host, port, secure, mode)
            val respA = exA.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val respB = exB.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val note = when {
                exA.error != null || exB.error != null ->
                    "One or both requests got no response (statuses/lengths are 0 for those). See errorA/errorB — add auth with session_set/cookie/headers, or check host/port/Host."
                exA.statusCode == exB.statusCode && respA == respB ->
                    "Responses are identical (same status, same bytes)."
                else -> "Responses differ — inspect diff, statuses and lengths."
            }
            Results.structured(
                SendCompareResult.serializer(),
                SendCompareResult(
                    idA = register("cmp", exA), idB = register("cmp", exB),
                    statusA = exA.statusCode, statusB = exB.statusCode,
                    lengthA = exA.responseBytes?.size ?: 0, lengthB = exB.responseBytes?.size ?: 0,
                    diff = HttpParse.diff(respA, respB),
                    reflectedA = HttpParse.findReflected(a, respA), reflectedB = HttpParse.findReflected(b, respB),
                    errorA = exA.error, errorB = exB.error, note = note,
                ),
            )
        }
    }

    companion object {
        private const val DESC_ANALYZE =
            "Send a raw HTTP request and get back, in ONE call: status, a parsed response, reflected-parameter " +
                "analysis, and a handle id to fetch the full body with get_http_message. Repeater + analysis fused."
        private const val DESC_COMPARE =
            "Send two request variants to the same target and return their statuses/lengths, a line diff of the " +
                "responses, and reflected params for each — one-call differential testing."
    }
}
