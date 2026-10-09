package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

/** Result of a programmatic send. [error] is non-null when the request produced no response (connection/TLS/
 *  protocol failure, timeout) — the reason a status/length comes back 0, instead of silently looking "identical". */
data class SentExchange(
    val statusCode: Int?,
    val mimeType: String?,
    val requestBytes: ByteArray,
    val responseBytes: ByteArray?,
    val error: String? = null,
)

@Serializable
data class CookieDTO(val name: String, val value: String, val domain: String, val path: String?)

@Serializable
data class OrganizerItemDTO(
    val id: Int,
    val status: String,
    val url: String? = null,
    val host: String? = null,
    val method: String? = null,
    val httpStatus: Int? = null,
    val notes: String? = null,
)

@Serializable
data class WsSendResult(val connected: Boolean, val upgradeStatus: Int? = null, val messages: List<String> = emptyList(), val note: String)

@Serializable
data class ImportOutcome(val status: String, val errors: List<String> = emptyList(), val ok: Boolean = true)

@Serializable
data class ProjectInfo(val name: String, val id: String)

/** Describes an issue to register in Burp from the agent (e.g. ingesting an external finding). */
data class NewIssue(
    val name: String,
    val detail: String,
    val remediation: String,
    val baseUrl: String,
    val severity: String,
    val confidence: String,
    val background: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val requestRaw: String?,
    val responseRaw: String?,
)

/** Mutating / outbound Burp operations, behind a seam so tool logic stays testable and the Montoya
 *  implementation is isolated. Every caller is gated by the unsafe switch + scope before reaching here. */
interface BurpActions {
    fun sendRequest(raw: String, host: String, port: Int, secure: Boolean, mode: String): SentExchange
    fun sendToRepeater(raw: String, host: String, port: Int, secure: Boolean, name: String?)
    fun sendToIntruder(raw: String, host: String, port: Int, secure: Boolean, name: String?)
    fun includeInScope(url: String)
    fun excludeFromScope(url: String)
    fun setIntercept(enabled: Boolean)
    fun isInterceptEnabled(): Boolean
    fun cookies(): List<CookieDTO>
    fun setCookie(name: String, value: String, domain: String, path: String?, expiresEpochSec: Long?)
    /** @return true if added, false if a duplicate (same name+baseUrl) already existed. */
    fun createIssue(issue: NewIssue): Boolean
    /** Insert a request/response into Burp's site map (e.g. a discovered endpoint). */
    fun addToSiteMap(raw: String, host: String, port: Int, secure: Boolean, responseRaw: String?)
    /** Send many requests in parallel (one batch); HTTP/2 mode enables Burp's single-packet coalescing. */
    fun sendParallel(requests: List<RawTarget>, mode: String): List<SentExchange>

    /**
     * Fire a batch with true HTTP/1.1 **last-byte synchronization** (clean-room [Http1RaceGate]) for the
     * tightest race windows Burp's batch send can't guarantee. Pure JDK networking, so the default impl needs
     * no Burp and is inherited by every seam implementation; test doubles may override it.
     */
    fun sendLastByteSync(requests: List<RawTarget>): List<SentExchange> {
        val resps = com.revoltsecurities.burpmcp.engine.Http1RaceGate.fire(
            requests.map { com.revoltsecurities.burpmcp.engine.Http1RaceGate.Req(it.raw, it.host, it.port, it.secure) },
        )
        return requests.mapIndexed { i, rt ->
            val r = resps.getOrNull(i)
            SentExchange(
                statusCode = r?.status,
                mimeType = null,
                requestBytes = rt.raw.toByteArray(Charsets.ISO_8859_1),
                responseBytes = r?.responseBytes,
                error = r?.error,
            )
        }
    }
    /** True if the managed high-throughput RequestExecutionEngine (Burp/montoya 2026.7+) is available. */
    fun managedEngineAvailable(): Boolean

    /**
     * Send a batch through Burp's managed `RequestExecutionEngine` — concurrency-limited, throttled and
     * retried — for controlled high-throughput fuzzing. [concurrency] <= 0 means the engine default;
     * [throttleMillis] <= 0 means no throttle. Default impl (and older Burp) falls back to a plain parallel
     * batch, so test doubles need not implement it.
     */
    fun sendManaged(requests: List<RawTarget>, concurrency: Int, throttleMillis: Long, maxRetries: Int): List<SentExchange> =
        sendParallel(requests, "auto")

    // ---- Phase 10 additions (default no-ops so test doubles stay simple; MontoyaActions overrides all) ----
    fun sendToOrganizer(raw: String, host: String, port: Int, secure: Boolean) {}
    fun organizerItems(): List<OrganizerItemDTO> = emptyList()
    fun wsSend(host: String, path: String, secure: Boolean, message: String, waitMs: Long): WsSendResult =
        WsSendResult(connected = false, note = "WebSocket send not supported by this implementation.")
    fun importBCheck(script: String, enabled: Boolean): ImportOutcome = ImportOutcome("UNSUPPORTED", ok = false)
    fun importBambda(script: String): ImportOutcome = ImportOutcome("UNSUPPORTED", ok = false)
    fun exportProjectOptions(): String = ""
    fun importProjectOptions(json: String) {}
    fun exportUserOptions(): String = ""
    fun importUserOptions(json: String) {}
    fun taskEngineGet(): String = ""
    fun taskEngineSet(state: String): String = ""
    fun persistenceGet(key: String): String? = null
    fun persistenceSet(key: String, value: String) {}
    fun persistenceKeys(): List<String> = emptyList()
    fun projectInfo(): ProjectInfo = ProjectInfo("", "")
}
