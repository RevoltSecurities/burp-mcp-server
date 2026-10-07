package com.revoltsecurities.burpmcp.tools

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Small JSON-Schema DSL producing a [ToolSchema] for a tool's inputs. Emits real descriptions, enums and
 * defaults so MCP clients get a meaningful tool contract (the reference project's reflection-based schema
 * dropped all of these).
 */
object SchemaBuilder {

    class Builder {
        val props = LinkedHashMap<String, JsonObject>()
        val required = mutableListOf<String>()

        fun string(name: String, description: String, enum: List<String>? = null, default: String? = null, required: Boolean = false) {
            props[name] = buildJsonObject {
                put("type", "string")
                put("description", description)
                if (enum != null) put("enum", buildJsonArray { enum.forEach { add(JsonPrimitive(it)) } })
                if (default != null) put("default", default)
            }
            if (required) this.required += name
        }

        fun integer(name: String, description: String, default: Int? = null, minimum: Int? = null, maximum: Int? = null, required: Boolean = false) {
            props[name] = buildJsonObject {
                put("type", "integer")
                put("description", description)
                if (default != null) put("default", default)
                if (minimum != null) put("minimum", minimum)
                if (maximum != null) put("maximum", maximum)
            }
            if (required) this.required += name
        }

        fun stringArray(name: String, description: String, required: Boolean = false) {
            props[name] = buildJsonObject {
                put("type", "array")
                put("description", description)
                put("items", buildJsonObject { put("type", "string") })
            }
            if (required) this.required += name
        }

        fun boolean(name: String, description: String, default: Boolean? = null) {
            props[name] = buildJsonObject {
                put("type", "boolean")
                put("description", description)
                if (default != null) put("default", default)
            }
        }
    }

    fun build(block: Builder.() -> Unit): ToolSchema {
        val b = Builder().apply(block)
        val properties = buildJsonObject { b.props.forEach { (k, v) -> put(k, v) } }
        return ToolSchema(
            SCHEMA_URI,
            properties,
            b.required.toList(),
            JsonObject(emptyMap()),
        )
    }

    /** An input schema with no parameters. */
    fun empty(): ToolSchema = ToolSchema(SCHEMA_URI, JsonObject(emptyMap()), emptyList(), JsonObject(emptyMap()))

    private const val SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"
}
