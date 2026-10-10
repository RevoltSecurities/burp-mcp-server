package com.revoltsecurities.burpmcp.tools

/**
 * Pure helpers for the HTTP send tools: degenerate-response detection, transport (HTTP-mode) auto-selection,
 * and edge/WAF signature extraction. Montoya-free so it is unit-testable with a fake [BurpActions].
 *
 * **Why this exists.** Burp surfaces a *failed transport* — a connection reset, a failed HTTP/2 (ALPN)
 * negotiation, or a WAF/edge RST — in two different shapes: either no response at all, OR a **degenerate
 * response** whose status line is `0` with an empty body (`hasResponse()` is true but the send really failed).
 * The send tools used to treat `error == null` as success, so a status-0 degenerate response was reported as
 * `ok:true` with no diagnostic — and `auto` mode (which negotiates HTTP/2 via ALPN) could silently fail on a
 * target whose HTTP/2 Burp can't complete, even though plain `http1` to the same target works. These helpers
 * make every send tool (a) recognise a status-0 result as the failure it is, and (b) when the caller asked for
 * `auto`, probe the other transports and use the one that actually returns a response.
 */
object HttpSend {

    const val AUTO = "auto"

    /** Modes tried, in order, when the caller asked for `auto` and a send degenerates. `auto` first (honour
     *  ALPN), then `http1` (most compatible — many ALBs/CDNs that break Burp's h2 still serve h1 fine), then
     *  forced h2 ignoring ALPN as a last resort. */
    val FALLBACK_MODES: List<String> = listOf(AUTO, "http1", "http2_ignore_alpn")

    /**
     * A send that did NOT yield a real HTTP response. True when Burp reported an outright error, returned no
     * status, or returned the synthetic `0` status (a failed transport surfaced as an empty response). No real
     * HTTP response ever has status 0, so this never misclassifies a genuine response.
     */
    fun isDegenerate(ex: SentExchange): Boolean =
        ex.error != null || ex.statusCode == null || ex.statusCode == 0

    /** True when a batch produced results and every one of them is degenerate (the whole send failed). */
    fun allDegenerate(list: List<SentExchange>): Boolean = list.isNotEmpty() && list.all { isDegenerate(it) }

    /** How many entries of a batch are degenerate (used for the accurate `failed` count). */
    fun degenerateCount(list: List<SentExchange>): Int = list.count { isDegenerate(it) }

    data class Selection(val mode: String, val exchange: SentExchange, val tried: List<String>) {
        val worked: Boolean get() = !isDegenerate(exchange)
        /** True when fallback changed the transport away from what the caller nominally requested. */
        fun switchedFrom(requested: String): Boolean = worked && tried.size > 1 && !mode.equals(requested, ignoreCase = true)
    }

    /**
     * Resolve the transport for a send. For an explicit (non-`auto`) [requested] mode, send once and return it
     * as-is — explicit means the caller is in control. For `auto`, probe each [FALLBACK_MODES] entry with a
     * single [send] until one returns a real response, and return that. If all fail, return the last attempt
     * (still degenerate) so the caller surfaces a clear transport diagnostic.
     */
    fun select(requested: String, autoRetry: Boolean = true, send: (mode: String) -> SentExchange): Selection {
        // No re-send when the caller pinned a mode, OR when auto-retry is disabled (non-idempotent request):
        // retrying a mutating request across transports could execute a state-changing action multiple times.
        if (!requested.equals(AUTO, ignoreCase = true) || !autoRetry) {
            return Selection(requested, send(requested), listOf(requested))
        }
        val tried = ArrayList<String>()
        var last: SentExchange? = null
        for (m in FALLBACK_MODES) {
            tried += m
            val ex = send(m)
            last = ex
            if (!isDegenerate(ex)) return Selection(m, ex, tried)
        }
        return Selection(AUTO, last!!, tried)
    }

    /** HTTP "safe" (idempotent, non-state-changing) methods — the only ones auto-fallback may re-send. */
    private val SAFE_METHODS = setOf("GET", "HEAD", "OPTIONS", "TRACE")

    /** Whether `auto` mode may safely re-send this request across transports (true only for safe methods). */
    fun autoRetryOk(method: String?): Boolean = method?.trim()?.uppercase() in SAFE_METHODS

    /**
     * If the response came from a recognisable edge/CDN/WAF layer, return its `Server` value (e.g.
     * `awselb/2.0`, `cloudfront`) so a block can be named in the diagnostic. Null when there's no response or
     * the server isn't a known edge. Parsed from the response head as ISO-8859-1 (byte-safe).
     */
    fun edgeSignature(ex: SentExchange): String? {
        val bytes = ex.responseBytes ?: return null
        val head = String(bytes, Charsets.ISO_8859_1).substringBefore("\r\n\r\n")
        val server = Regex("(?im)^server:[ \\t]*(.+?)[ \\t]*$").find(head)?.groupValues?.get(1)?.trim() ?: return null
        val s = server.lowercase()
        val isEdge = EDGE_VENDORS.any { it in s }
        return if (isEdge) server else null
    }

    private val EDGE_VENDORS = listOf(
        "awselb", "cloudfront", "cloudflare", "akamai", "imperva", "incapsula",
        "fastly", "sucuri", "barracuda", "f5", "big-ip", "mod_security", "modsecurity",
    )

    /** Diagnostic for a send whose transport failed, naming the modes tried and the right next step. */
    fun transportFailureNote(tried: List<String>, edge: String? = null): String = buildString {
        append("No usable HTTP response — the transport failed (connection reset / TLS / failed HTTP/2 (ALPN) ")
        append("negotiation / WAF reset). statusText is \"no response\"; this is NOT a 0 status code. ")
        if (tried.size > 1) append("Tried httpMode ${tried.joinToString()} and all failed. ")
        if (edge != null) append("The edge responded as '$edge' (likely a WAF/edge block). ")
        append("If the target rejects Burp's HTTP/2, retry with httpMode=http1.")
    }
}
