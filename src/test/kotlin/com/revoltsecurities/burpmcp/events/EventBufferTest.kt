package com.revoltsecurities.burpmcp.events

import com.revoltsecurities.burpmcp.tools.Args
import com.revoltsecurities.burpmcp.tools.EventTools
import com.revoltsecurities.burpmcp.tools.EventsResult
import com.revoltsecurities.burpmcp.tools.Results
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EventBufferTest {

    @Test
    fun `records are sequenced and read forward from a cursor`() {
        val b = EventBuffer()
        b.record("http", "a"); b.record("http", "b"); b.record("issue", "c")
        assertEquals(3, b.lastSeq())
        val afterFirst = b.since(1, 10)
        assertEquals(listOf("b", "c"), afterFirst.map { it.summary })
    }

    @Test
    fun `kind filter works`() {
        val b = EventBuffer()
        b.record("http", "a"); b.record("issue", "x"); b.record("http", "b")
        assertEquals(listOf("x"), b.since(0, 10, "issue").map { it.summary })
    }

    @Test
    fun `respects capacity (ring buffer drops oldest)`() {
        val b = EventBuffer(capacity = 3)
        repeat(5) { b.record("http", "e$it") }
        assertEquals(3, b.size())
        assertEquals(5, b.lastSeq())
        // oldest dropped; only last 3 remain
        assertEquals(listOf("e2", "e3", "e4"), b.since(0, 10).map { it.summary })
    }

    @Test
    fun `events_poll tool returns events and lastSeq`() {
        val b = EventBuffer()
        b.record("http", "GET / -> 200", "GET", "https://x/", 200)
        val tool = EventTools.build(b).single()
        val res = runBlocking { tool.handler(Args(buildJsonObject { put("afterSeq", JsonPrimitive(0)) })) }
        val r = Results.json.decodeFromJsonElement(EventsResult.serializer(), res.structuredContent!!)
        assertEquals(1, r.returned)
        assertEquals(1L, r.lastSeq)
        assertTrue(r.events.first().summary.contains("GET /"))
    }
}
