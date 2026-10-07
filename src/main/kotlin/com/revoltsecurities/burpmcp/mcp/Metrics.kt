package com.revoltsecurities.burpmcp.mcp

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** Simple in-memory counters for the dashboard/status. */
class Metrics {
    private val total = AtomicLong(0)
    private val perTool = ConcurrentHashMap<String, AtomicLong>()

    fun record(toolId: String) {
        total.incrementAndGet()
        perTool.computeIfAbsent(toolId) { AtomicLong(0) }.incrementAndGet()
    }

    fun totalCalls(): Long = total.get()
    fun perTool(): Map<String, Long> = perTool.mapValues { it.value.get() }
}
