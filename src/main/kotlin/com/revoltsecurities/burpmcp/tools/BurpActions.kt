package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.Serializable

/** Result of a programmatic send. */
data class SentExchange(
    val statusCode: Int?,
    val mimeType: String?,
    val requestBytes: ByteArray,
    val responseBytes: ByteArray?,
)

@Serializable
data class CookieDTO(val name: String, val value: String, val domain: String, val path: String?)

@Serializable
data class OrganizerItemDTO(val id: Int, val status: String)

@Serializable
data class WsSendResult(val connected: Boolean, val upgradeStatus: Int? = null, val messages: List<String> = emptyList(), val note: String)

@Serializable
data class ImportOutcome(val status: String, val errors: List<String> = emptyList())

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
    /** True if the managed high-throughput RequestExecutionEngine (Burp/montoya 2026.7+) is available. */
    fun managedEngineAvailable(): Boolean

    // ---- Phase 10 additions (default no-ops so test doubles stay simple; MontoyaActions overrides all) ----
    fun sendToOrganizer(raw: String, host: String, port: Int, secure: Boolean) {}
    fun organizerItems(): List<OrganizerItemDTO> = emptyList()
    fun wsSend(host: String, path: String, secure: Boolean, message: String, waitMs: Long): WsSendResult =
        WsSendResult(connected = false, note = "WebSocket send not supported by this implementation.")
    fun importBCheck(script: String, enabled: Boolean): ImportOutcome = ImportOutcome("UNSUPPORTED")
    fun importBambda(script: String): ImportOutcome = ImportOutcome("UNSUPPORTED")
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
