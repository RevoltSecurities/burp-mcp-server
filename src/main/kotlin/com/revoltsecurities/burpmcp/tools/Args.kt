package com.revoltsecurities.burpmcp.tools

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/** Null-safe accessor over a tool-call arguments object. Missing/typed-wrong values fall back to defaults. */
class Args(private val json: JsonObject) {

    /** The underlying arguments object (for pass-through, e.g. federated tool calls). */
    fun raw(): JsonObject = json

    private fun prim(key: String): JsonPrimitive? = (json[key] as? JsonPrimitive)

    fun str(key: String): String? = prim(key)?.let { if (it.isString) it.content else null }?.takeIf { it.isNotEmpty() }
    fun strOr(key: String, default: String): String = str(key) ?: default

    fun int(key: String): Int? = prim(key)?.intOrNull
    fun intOr(key: String, default: Int): Int = int(key) ?: default

    /**
     * Read a 64-bit integer. Use this (not [int]) for values that can exceed Int range: unix-second
     * timestamps past 2038-01-19, event sequence numbers, byte offsets. Falls back to [int] so a value that
     * fits in an Int still parses, but a large long is no longer silently dropped to null.
     */
    fun long(key: String): Long? = prim(key)?.let { it.longOrNull ?: it.intOrNull?.toLong() }
    fun longOr(key: String, default: Long): Long = long(key) ?: default

    fun bool(key: String): Boolean? = prim(key)?.booleanOrNull
    fun boolOr(key: String, default: Boolean): Boolean = bool(key) ?: default

    fun require(key: String): String =
        str(key) ?: throw IllegalArgumentException("Missing required argument '$key'")

    /** Read a JSON array of strings; empty list if absent or wrong type. */
    fun strList(key: String): List<String> {
        val arr = json[key] as? JsonArray ?: return emptyList()
        return arr.mapNotNull { (it as? JsonPrimitive)?.let { p -> if (p.isString) p.content else null } }
    }
}
