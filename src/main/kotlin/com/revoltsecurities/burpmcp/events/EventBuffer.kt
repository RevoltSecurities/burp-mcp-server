package com.revoltsecurities.burpmcp.events

import kotlinx.serialization.Serializable

/** A lightweight Burp event (HTTP response seen, new scan issue, …) for streaming to agents via events_poll. */
@Serializable
data class BurpEvent(
    val seq: Long,
    val kind: String,
    val summary: String,
    val method: String? = null,
    val url: String? = null,
    val status: Int? = null,
    val severity: String? = null,
    val epochMs: Long,
)

/**
 * Bounded, monotonically-sequenced ring buffer of events. Montoya handlers push summaries in (off-EDT);
 * the events_poll tool reads forward from a cursor (seq). Pure and unit-testable.
 */
class EventBuffer(private val capacity: Int = DEFAULT_CAPACITY) {

    private val lock = Any()
    private val items = ArrayDeque<BurpEvent>()
    private var seq = 0L

    fun record(kind: String, summary: String, method: String? = null, url: String? = null, status: Int? = null, severity: String? = null) {
        synchronized(lock) {
            seq += 1
            items.addLast(BurpEvent(seq, kind, summary, method, url, status, severity, System.currentTimeMillis()))
            while (items.size > capacity) items.removeFirst()
        }
    }

    /** Events with seq > [afterSeq], optionally filtered by kind, up to [limit]. */
    fun since(afterSeq: Long, limit: Int, kind: String? = null): List<BurpEvent> = synchronized(lock) {
        items.asSequence()
            .filter { it.seq > afterSeq && (kind == null || it.kind == kind) }
            .take(limit)
            .toList()
    }

    fun lastSeq(): Long = synchronized(lock) { seq }

    fun size(): Int = synchronized(lock) { items.size }

    companion object {
        const val DEFAULT_CAPACITY = 2_000
    }
}
