package com.revoltsecurities.burpmcp.tools

import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/** Helpers for building [CallToolResult]s with both a text block and structured content. */
object Results {

    val json = Json {
        encodeDefaults = true
        explicitNulls = false
    }

    fun text(message: String): CallToolResult =
        CallToolResult(listOf(TextContent(message)))

    fun error(message: String): CallToolResult =
        CallToolResult(listOf(TextContent(message)), true)

    /**
     * Dual output: the JSON mirrored into a text block, plus structuredContent when the value serializes to a
     * JSON object. (MCP structuredContent must be an object; array/primitive results are text-only.)
     */
    fun <T> structured(serializer: SerializationStrategy<T>, value: T): CallToolResult {
        val textForm = json.encodeToString(serializer, value)
        val obj = json.encodeToJsonElement(serializer, value) as? JsonObject
        return CallToolResult(listOf(TextContent(textForm)), null, obj)
    }

    /** Structured content flagged as an error (isError=true) — keeps the typed payload while signalling failure. */
    fun <T> structuredError(serializer: SerializationStrategy<T>, value: T): CallToolResult {
        val base = structured(serializer, value)
        return CallToolResult(base.content, true, base.structuredContent)
    }
}
