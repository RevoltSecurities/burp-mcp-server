package com.revoltsecurities.burpmcp.integrations

import com.revoltsecurities.burpmcp.tools.BambdaRepo
import com.revoltsecurities.burpmcp.tools.BambdaRepoEntry
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.contentLength
import io.ktor.http.isSuccess
import io.ktor.utils.io.readAvailable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * [BambdaRepo] backed by the public PortSwigger/bambdas GitHub repo. Host and repo are hard-coded: listing hits
 * `api.github.com` (one recursive-tree call, cached ~10 min to respect the 60/hr anon limit) and fetching hits
 * `raw.githubusercontent.com` (not API-rate-limited). Redirects are disabled and only a validated repo-relative
 * `.bambda` path is ever appended — no arbitrary-URL fetch. Non-2xx responses THROW (so the tool surfaces an
 * error) rather than being mistaken for content or an empty repo.
 */
class GithubBambdaRepo : BambdaRepo {

    private val client = HttpClient(CIO) { followRedirects = false }
    private val json = Json { ignoreUnknownKeys = true }

    // Single @Volatile holder so readers never see a fresh list paired with a stale timestamp.
    @Volatile
    private var cached: Cached? = null

    override suspend fun listScripts(): List<BambdaRepoEntry> {
        cached?.let { if (System.currentTimeMillis() - it.at < CACHE_TTL_MS) return it.entries }
        val url = "https://api.github.com/repos/${BambdaRepo.REPO}/git/trees/${BambdaRepo.BRANCH}?recursive=1"
        val resp = client.get(url) {
            header("User-Agent", "revolt-mcp-server")
            header("Accept", "application/vnd.github+json")
        }
        if (!resp.status.isSuccess()) {
            error("GitHub API returned ${resp.status.value} listing bambdas (likely the 60/hr anonymous rate limit — retry shortly).")
        }
        val root = json.parseToJsonElement(readCapped(resp)).jsonObject
        val tree = root["tree"]?.jsonArray ?: error("Unexpected GitHub tree response (no 'tree').")
        val entries = tree.mapNotNull { node ->
            val obj = node.jsonObject
            val path = obj["path"]?.jsonPrimitive?.content ?: return@mapNotNull null
            if (obj["type"]?.jsonPrimitive?.content != "blob" || !path.endsWith(".bambda")) return@mapNotNull null
            BambdaRepoEntry(path = path, name = path.substringAfterLast('/'), category = BambdaRepo.categoryOf(path))
        }.sortedBy { it.path }
        // Cache only a COMPLETE result on success. (The bambdas repo is tiny, so GitHub never truncates it; if
        // it ever did we simply don't cache, so the next call retries.)
        val truncated = root["truncated"]?.jsonPrimitive?.booleanOrNull == true
        if (!truncated) cached = Cached(System.currentTimeMillis(), entries)
        return entries
    }

    override suspend fun fetch(path: String): String {
        val safe = BambdaRepo.safePath(path)
        val url = "https://raw.githubusercontent.com/${BambdaRepo.REPO}/${BambdaRepo.BRANCH}/$safe"
        val resp: HttpResponse = client.get(url) { header("User-Agent", "revolt-mcp-server") }
        if (!resp.status.isSuccess()) {
            error("GitHub returned ${resp.status.value} for '$safe' (not found, or rate-limited).")
        }
        return readCapped(resp)
    }

    /**
     * Read the body with a hard byte cap enforced during streaming — so a chunked / no-Content-Length response
     * (where the header check alone wouldn't fire) still can't balloon the heap. Rejects an oversized
     * Content-Length up front as a fast path.
     */
    private suspend fun readCapped(resp: HttpResponse): String {
        resp.contentLength()?.let { if (it > MAX_BODY_BYTES) error("GitHub response is $it bytes, exceeding the ${MAX_BODY_BYTES}-byte cap.") }
        val channel = resp.bodyAsChannel()
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        var total = 0L
        while (true) {
            val n = channel.readAvailable(buf, 0, buf.size)
            if (n == -1) break
            if (n > 0) {
                total += n
                if (total > MAX_BODY_BYTES) error("GitHub response exceeds the ${MAX_BODY_BYTES}-byte cap for bambda fetches.")
                out.write(buf, 0, n)
            }
        }
        return out.toString(Charsets.UTF_8.name())
    }

    fun close() = client.close()

    private data class Cached(val at: Long, val entries: List<BambdaRepoEntry>)

    private companion object {
        const val CACHE_TTL_MS = 600_000L
        const val MAX_BODY_BYTES = 10_000_000L
    }
}
