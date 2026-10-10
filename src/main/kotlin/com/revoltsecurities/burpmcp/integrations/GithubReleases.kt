package com.revoltsecurities.burpmcp.integrations

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** The latest published release, as reported by GitHub. */
data class LatestRelease(val tag: String, val version: String, val notes: String, val url: String)

/** Pure parser for GitHub's `releases/latest` JSON → [LatestRelease]. Returns null on ANY malformed input. */
object GithubReleaseParse {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(body: String): LatestRelease? = runCatching {
        val o = json.parseToJsonElement(body).jsonObject
        val tag = o["tag_name"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: return@runCatching null
        val notes = o["body"]?.jsonPrimitive?.contentOrNull ?: ""
        val url = o["html_url"]?.jsonPrimitive?.contentOrNull ?: ""
        LatestRelease(tag = tag, version = tag.trimStart('v', 'V'), notes = notes, url = url)
    }.getOrNull()
}

/**
 * Best-effort fetch of the project's latest GitHub release (host-pinned to api.github.com, redirects off). Used
 * only by the dashboard update check — returns null on any failure (offline, rate-limited, parse error) so the
 * UI degrades silently. GitHub's `releases/latest` excludes pre-releases, so the result is always a stable tag.
 */
class GithubReleases(private val repo: String = "RevoltSecurities/burp-mcp-server") {

    // Lazy + synchronized: no CIO engine/thread-pool is allocated until an update check actually runs, so a
    // user who disabled the check pays no startup cost.
    @Volatile
    private var client: HttpClient? = null

    private fun client(): HttpClient = client ?: synchronized(this) { client ?: GithubHttp.newClient().also { client = it } }

    suspend fun latest(): LatestRelease? = runCatching {
        val resp = client().get("https://api.github.com/repos/$repo/releases/latest") {
            header("User-Agent", "revolt-mcp-server")
            header("Accept", "application/vnd.github+json")
        }
        if (!resp.status.isSuccess()) return null
        GithubReleaseParse.parse(resp.bodyAsText())
    }.getOrNull()

    fun close() {
        runCatching { client?.close() }
    }
}
