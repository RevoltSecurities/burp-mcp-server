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
    val httpModeUsed: String? = null,
    val targetHost: String? = null,
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
    val httpModeUsed: String? = null,
    val targetHost: String? = null,
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
            string("host", Descriptions.TARGET_HOST_OPT)
            integer("port", Descriptions.TARGET_PORT_OPT)
            boolean("secure", Descriptions.TARGET_SECURE_OPT, default = true)
            structuredRequestParams()
            string("cookie", Descriptions.SESSION_COOKIE)
            string("httpMode", Descriptions.HTTP_MODE, enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send_analyze", "Send + analyze", DESC_ANALYZE, "Requests", schema, mutating = true) { args ->
            val r = RequestBuilder.fromArgs(args)
            val t = TargetArgs.Target(r.host, r.port, r.secure)
            guard.reject(t.host, t.port, t.secure)?.let { return@ToolSpec it }
            val content = inject(args, r.raw, t.host)
            val requestedMode = args.strOr("httpMode", "auto")
            val autoRetry = HttpSend.autoRetryOk(HttpParse.parseRequest(content, includeBody = false).method)
            val sel = HttpSend.select(requestedMode, autoRetry) { m -> actions.sendRequest(content, t.host, t.port, t.secure, m) }
            val ex = sel.exchange
            val ok = sel.worked
            val respText = ex.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val id = register("ana", ex)
            val edge = HttpSend.edgeSignature(ex)
            val note = buildString {
                if (!ok) append(HttpSend.transportFailureNote(sel.tried, edge))
                else {
                    if (sel.switchedFrom(requestedMode)) append("Auto-selected httpMode=${sel.mode}. ")
                    if (edge != null) append("Served via an edge/WAF layer (server=$edge). ")
                    append("Full response: get_http_message id=$id part=response section=body.")
                }
            }
            val result = SendAnalyzeResult(
                id = id, ok = ok, status = ex.statusCode, statusText = if (ok) (ex.statusCode?.toString() ?: "no response") else "no response",
                mimeType = ex.mimeType, responseLength = ex.responseBytes?.size ?: 0,
                reflected = HttpParse.findReflected(content, respText),
                response = HttpParse.parseResponse(respText, includeBody = false),
                note = note,
                error = if (ok) null else (ex.error ?: "transport failed (no HTTP response; status 0)"),
                httpModeUsed = sel.mode,
                targetHost = t.host,
            )
            if (result.ok) Results.structured(SendAnalyzeResult.serializer(), result) else Results.structuredError(SendAnalyzeResult.serializer(), result)
        }
    }

    private fun sendCompare(): ToolSpec {
        val schema = SchemaBuilder.build {
            string("host", "Shared target host for both requests (or give urlA/urlB). " + Descriptions.TARGET_HOST_OPT)
            integer("port", Descriptions.TARGET_PORT_OPT)
            boolean("secure", Descriptions.TARGET_SECURE_OPT, default = true)
            stringArray("headers", Descriptions.REQUEST_HEADERS)
            string("httpVersion", Descriptions.BUILD_HTTP_VERSION, enum = listOf("HTTP/1.1", "HTTP/2"), default = "HTTP/1.1")
            structuredRequestParamsSuffixed("A")
            structuredRequestParamsSuffixed("B")
            string("cookie", Descriptions.SESSION_COOKIE)
            string("httpMode", Descriptions.HTTP_MODE, enum = listOf("auto", "http1", "http2", "http2_ignore_alpn"), default = "auto")
        }
        return ToolSpec("http_send_compare", "Send + compare", DESC_COMPARE, "Requests", schema, mutating = true) { args ->
            val sideA = RequestBuilder.fromArgsSide(args, "A")
            val sideB = RequestBuilder.fromArgsSide(args, "B")
            val tA = TargetArgs.Target(sideA.host, sideA.port, sideA.secure)
            val tB = TargetArgs.Target(sideB.host, sideB.port, sideB.secure)
            // Scope-check BOTH targets — side B may legitimately point at a different host.
            guard.reject(tA.host, tA.port, tA.secure)?.let { return@ToolSpec it }
            guard.reject(tB.host, tB.port, tB.secure)?.let { return@ToolSpec it }
            val requestedMode = args.strOr("httpMode", "auto")
            val a = inject(args, sideA.raw, tA.host); val b = inject(args, sideB.raw, tB.host)
            // Pick the transport with a single probe on A (auto-retry only for safe methods — a mutating A is
            // never re-sent), then send each side to ITS OWN resolved target in that mode.
            val autoRetry = HttpSend.autoRetryOk(HttpParse.parseRequest(a, includeBody = false).method)
            val sel = HttpSend.select(requestedMode, autoRetry) { m -> actions.sendRequest(a, tA.host, tA.port, tA.secure, m) }
            val exA = sel.exchange
            val exB = actions.sendRequest(b, tB.host, tB.port, tB.secure, sel.mode)
            val respA = exA.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val respB = exB.responseBytes?.toString(Charsets.UTF_8) ?: ""
            val degenA = HttpSend.isDegenerate(exA); val degenB = HttpSend.isDegenerate(exB)
            val ok = !degenA && !degenB
            val edge = HttpSend.edgeSignature(exA) ?: HttpSend.edgeSignature(exB)
            val identical = exA.statusCode == exB.statusCode && respA == respB
            val note = buildString {
                when {
                    !ok -> append("One or both requests got NO HTTP response (transport failed; status 0). See errorA/errorB — this is NOT a 0 status code. Retry with httpMode=http1, or add auth via session_set/cookie/headers.")
                    identical -> {
                        append("Responses are IDENTICAL (status ${exA.statusCode}, ${respA.length} bytes). ")
                        if (edge != null) append("Both served by an edge/WAF layer (server=$edge) — this looks like a WAF/edge block rejecting every variant, so the differential is NOT meaningful; switch to a browser-proxied path or a different egress for this target. ")
                        else append("No differential signal — the variants are indistinguishable to the target. ")
                    }
                    else -> append("Responses differ — inspect diff, statuses and lengths.")
                }
                if (ok && sel.switchedFrom(requestedMode)) append("(Auto-selected httpMode=${sel.mode}.)")
            }
            val result = SendCompareResult(
                idA = register("cmp", exA), idB = register("cmp", exB), ok = ok,
                statusA = exA.statusCode, statusB = exB.statusCode,
                statusTextA = if (degenA) "no response" else (exA.statusCode?.toString() ?: "no response"),
                statusTextB = if (degenB) "no response" else (exB.statusCode?.toString() ?: "no response"),
                lengthA = exA.responseBytes?.size ?: 0, lengthB = exB.responseBytes?.size ?: 0,
                diff = HttpParse.diff(respA, respB),
                reflectedA = HttpParse.findReflected(a, respA), reflectedB = HttpParse.findReflected(b, respB),
                errorA = if (degenA) (exA.error ?: "transport failed (status 0)") else null,
                errorB = if (degenB) (exB.error ?: "transport failed (status 0)") else null,
                note = note, httpModeUsed = sel.mode, targetHost = if (tA.host == tB.host) tA.host else "${tA.host} vs ${tB.host}",
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
