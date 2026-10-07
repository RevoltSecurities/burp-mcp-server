package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.output.BodySlicer
import com.revoltsecurities.burpmcp.output.MessageRegistry
import com.revoltsecurities.burpmcp.output.TruncationMarker
import kotlinx.serialization.Serializable

@Serializable
data class HttpMessageResult(
    val id: String,
    val part: String,
    val section: String,
    val mimeType: String? = null,
    val totalBytes: Int,
    val headerBytes: Int,
    val bodyBytes: Int,
    val bodyEncoding: String? = null,
    val bodyOffset: Int? = null,
    val bodyLength: Int? = null,
    val headers: String? = null,
    val content: String? = null,
    val truncation: TruncationMarker? = null,
)

/**
 * `get_http_message`: fetch a request/response by its row `id` in bounded, resumable byte slices. The one
 * path by which raw bytes ever leave the server — lists only ever carry ids. Binary bodies are omitted.
 */
object HttpMessageTool {

    private val CRLF_CRLF = "\r\n\r\n".toByteArray(Charsets.ISO_8859_1)

    fun build(registry: MessageRegistry, cfg: ToolConfig): ToolSpec {
        val schema = SchemaBuilder.build {
            string("id", Descriptions.MESSAGE_ID, required = true)
            string("part", "Which half of the exchange to read.", enum = listOf("request", "response"), default = "response")
            string(
                "section",
                "What to return: \"meta\" = sizes/mime only (start here, zero body); \"headers\" = header block; " +
                    "\"body\" = the sliced body; \"full\" = headers + sliced body.",
                enum = listOf("meta", "headers", "body", "full"),
                default = "meta",
            )
            integer("offset", "Byte offset into the body (for section=body/full). Use the truncation.nextAction offset to continue.", default = 0, minimum = 0)
            integer("length", "Max body bytes to return this call (server cap ${cfg.maxSliceBytes}).", default = cfg.defaultSliceBytes, minimum = 1, maximum = cfg.maxSliceBytes)
        }
        return ToolSpec(
            id = "get_http_message",
            title = "Get HTTP message",
            description = "Fetch a request or response by its id (from a list tool) in bounded, resumable byte " +
                "slices. Use section=meta first to see sizes, then section=body with offset/length to page the body.",
            category = "Output",
            inputSchema = schema,
        ) { args -> handle(args, registry, cfg) }
    }

    private fun handle(args: Args, registry: MessageRegistry, cfg: ToolConfig): io.modelcontextprotocol.kotlin.sdk.types.CallToolResult {
        val id = args.require("id")
        val part = args.strOr("part", "response").lowercase()
        val section = args.strOr("section", "meta").lowercase()
        val offset = args.intOr("offset", 0).coerceAtLeast(0)
        val length = args.intOr("length", cfg.defaultSliceBytes).coerceIn(1, cfg.maxSliceBytes)

        val handle = registry.get(id)
            ?: return Results.error("Unknown id '$id'. Re-run the relevant list tool to refresh ids, then retry.")

        val bytes = when (part) {
            "request" -> handle.requestBytes()
            "response" -> handle.responseBytes()
            else -> return Results.error("Invalid part '$part' (use request|response).")
        } ?: return Results.error("No $part bytes available for '$id'.")

        val split = splitHeaderBody(bytes)
        val headerStr = String(split.first, Charsets.UTF_8)
        val body = split.second

        val result = when (section) {
            "meta" -> HttpMessageResult(
                id = id, part = part, section = section, mimeType = handle.mimeType,
                totalBytes = bytes.size, headerBytes = split.first.size, bodyBytes = body.size,
            )
            "headers" -> HttpMessageResult(
                id = id, part = part, section = section, mimeType = handle.mimeType,
                totalBytes = bytes.size, headerBytes = split.first.size, bodyBytes = body.size,
                headers = capHeaders(headerStr, cfg.maxSliceBytes),
            )
            "body", "full" -> {
                val slice = BodySlicer.slice(
                    bytes = body, offset = offset, length = length, mimeType = handle.mimeType,
                    maxLength = cfg.maxSliceBytes,
                ) { next -> "get_http_message id=$id part=$part section=body offset=$next length=$length" }
                HttpMessageResult(
                    id = id, part = part, section = section, mimeType = handle.mimeType,
                    totalBytes = bytes.size, headerBytes = split.first.size, bodyBytes = body.size,
                    bodyEncoding = slice.encoding.name.lowercase(),
                    bodyOffset = slice.offset, bodyLength = slice.length,
                    headers = if (section == "full") capHeaders(headerStr, cfg.maxSliceBytes) else null,
                    content = slice.content,
                    truncation = slice.truncation,
                )
            }
            else -> return Results.error("Invalid section '$section' (use meta|headers|body|full).")
        }
        return Results.structured(HttpMessageResult.serializer(), result)
    }

    /** Split raw HTTP bytes at the first CRLFCRLF into (headers, body). */
    private fun splitHeaderBody(bytes: ByteArray): Pair<ByteArray, ByteArray> {
        val idx = indexOf(bytes, CRLF_CRLF)
        return if (idx < 0) {
            bytes to ByteArray(0)
        } else {
            bytes.copyOfRange(0, idx) to bytes.copyOfRange(idx + CRLF_CRLF.size, bytes.size)
        }
    }

    private fun capHeaders(headers: String, max: Int): String =
        if (headers.length <= max) headers else headers.take(max) + "\n…(headers truncated)"

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || haystack.size < needle.size) return -1
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}

/** Limits for list + body-slice tools, sourced from settings. */
data class ToolConfig(
    val defaultLimit: Int,
    val maxLimit: Int,
    val maxToolResultBytes: Int,
    val defaultSliceBytes: Int,
    val maxSliceBytes: Int,
)
