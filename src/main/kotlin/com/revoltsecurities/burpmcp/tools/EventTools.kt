package com.revoltsecurities.burpmcp.tools

import com.revoltsecurities.burpmcp.events.BurpEvent
import com.revoltsecurities.burpmcp.events.EventBuffer
import kotlinx.serialization.Serializable

@Serializable
data class EventsResult(val events: List<BurpEvent>, val lastSeq: Long, val returned: Int)

/** Lightweight tool metadata for the UI tool-toggle grid (no handlers). Derived from the live spec list. */
data class ToolMeta(
    val id: String,
    val title: String,
    val category: String,
    val mutating: Boolean,
    val proOnly: Boolean,
    val defaultEnabled: Boolean,
)

/** `events_poll`: stream Burp events (HTTP responses, new scan issues) forward from a cursor. */
object EventTools {

    fun build(buffer: EventBuffer): List<ToolSpec> = listOf(eventsPoll(buffer))

    private fun eventsPoll(buffer: EventBuffer): ToolSpec {
        val schema = SchemaBuilder.build {
            integer("afterSeq", "Return events with seq greater than this (0 = from the start of the buffer).", default = 0, minimum = 0)
            integer("limit", "Max events to return.", default = 50, minimum = 1, maximum = 200)
            string("kind", "Filter by event kind.", enum = listOf("http", "issue"))
        }
        return ToolSpec("events_poll", "Poll events", "Stream recent Burp events (HTTP responses, new scan issues) forward from a cursor seq.", "Events", schema) { args ->
            val after = args.longOr("afterSeq", 0L)
            val limit = args.intOr("limit", 50).coerceIn(1, 200)
            val events = buffer.since(after, limit, args.str("kind"))
            Results.structured(EventsResult.serializer(), EventsResult(events, buffer.lastSeq(), events.size))
        }
    }
}
