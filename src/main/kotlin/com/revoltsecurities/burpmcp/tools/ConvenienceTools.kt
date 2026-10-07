package com.revoltsecurities.burpmcp.tools

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
)

/** Repeater-style one-call send-and-analyze helpers (mutating, scope-gated). */
class ConvenienceTools(
    private val actions: BurpActions,
    private val registry: MessageRegistry,
    private val guard: ScopeGuard,
) {
    private val counter = AtomicInteger(0)

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
            string("httpMode", "Protocol mode.", enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send_analyze", "Send + analyze", DESC_ANALYZE, "Requests", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = guard.resolvePort(args.int("port"), secure)
            guard.reject(host, port, secure)?.let { return@ToolSpec it }
            val content = args.require("content")
            val ex = actions.sendRequest(content, host, port, secure, args.strOr("httpMode", "auto"))
            val respText = ex.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val id = register("ana", ex)
            Results.structured(
                SendAnalyzeResult.serializer(),
                SendAnalyzeResult(
                    id = id, status = ex.statusCode, mimeType = ex.mimeType, responseLength = ex.responseBytes?.size ?: 0,
                    reflected = HttpParse.findReflected(content, respText),
                    response = HttpParse.parseResponse(respText, includeBody = false),
                    note = "Full response: get_http_message id=$id part=response section=body.",
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
            string("httpMode", "Protocol mode.", enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send_compare", "Send + compare", DESC_COMPARE, "Requests", schema, mutating = true) { args ->
            val host = args.require("host"); val secure = args.boolOr("secure", true); val port = guard.resolvePort(args.int("port"), secure)
            guard.reject(host, port, secure)?.let { return@ToolSpec it }
            val mode = args.strOr("httpMode", "auto")
            val a = args.require("contentA"); val b = args.require("contentB")
            val exA = actions.sendRequest(a, host, port, secure, mode)
            val exB = actions.sendRequest(b, host, port, secure, mode)
            val respA = exA.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val respB = exB.responseBytes?.toString(Charsets.UTF_8) ?: ""
            Results.structured(
                SendCompareResult.serializer(),
                SendCompareResult(
                    idA = register("cmp", exA), idB = register("cmp", exB),
                    statusA = exA.statusCode, statusB = exB.statusCode,
                    lengthA = exA.responseBytes?.size ?: 0, lengthB = exB.responseBytes?.size ?: 0,
                    diff = HttpParse.diff(respA, respB),
                    reflectedA = HttpParse.findReflected(a, respA), reflectedB = HttpParse.findReflected(b, respB),
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
