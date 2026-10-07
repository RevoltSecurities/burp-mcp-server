package com.revoltsecurities.burpmcp.integrations

import com.revoltsecurities.burpmcp.tools.NewIssue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI

/** Pure parser: nuclei JSONL export → [NewIssue]s ready for `siteMap.add` via BurpActions.createIssue. */
object NucleiIngest {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    fun parse(jsonl: String): List<NewIssue> =
        jsonl.lineSequence().map { it.trim() }.filter { it.startsWith("{") }.mapNotNull { line ->
            runCatching { toIssue(json.parseToJsonElement(line).jsonObject) }.getOrNull()
        }.toList()

    private fun toIssue(o: JsonObject): NewIssue {
        val info = o["info"]?.jsonObject
        fun s(obj: JsonObject?, key: String): String? = obj?.get(key)?.let { runCatching { it.jsonPrimitive.contentOrNull }.getOrNull() }
        val templateId = s(o, "template-id") ?: s(o, "templateID")
        val name = s(info, "name") ?: templateId ?: "Nuclei finding"
        val severity = mapSeverity(s(info, "severity"))
        val host = s(o, "host") ?: ""
        val matchedAt = s(o, "matched-at") ?: s(o, "matched_at") ?: host
        val baseUrl = matchedAt.ifEmpty { host }
        val detail = buildString {
            appendLine("Imported from nuclei.")
            templateId?.let { appendLine("template-id: $it") }
            if (matchedAt.isNotEmpty()) appendLine("matched-at: $matchedAt")
            s(info, "description")?.let { appendLine("description: $it") }
            s(o, "extracted-results")?.let { appendLine("extracted: $it") }
            s(o, "curl-command")?.let { append("curl: $it") }
        }.trim()
        val (h, p, secure) = parseTarget(baseUrl)
        return NewIssue(
            name = "[nuclei] $name",
            detail = detail,
            remediation = s(info, "remediation") ?: "",
            baseUrl = baseUrl,
            severity = severity,
            confidence = "firm",
            background = "Imported from an external nuclei scan.",
            host = h, port = p, secure = secure,
            requestRaw = s(o, "request"),
            responseRaw = s(o, "response"),
        )
    }

    private fun mapSeverity(sev: String?): String = when (sev?.lowercase()) {
        "critical", "high" -> "high"
        "medium" -> "medium"
        "low" -> "low"
        else -> "information"
    }

    private fun parseTarget(url: String): Triple<String, Int, Boolean> {
        val uri = runCatching { URI(url) }.getOrNull()
        val secure = (uri?.scheme ?: "https").equals("https", ignoreCase = true)
        val host = uri?.host ?: url.substringAfter("://", url).substringBefore('/').substringBefore(':')
        val port = uri?.port?.takeIf { it > 0 } ?: if (secure) 443 else 80
        return Triple(host, port, secure)
    }
}
