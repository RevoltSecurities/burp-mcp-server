package com.revoltsecurities.burpmcp.tools

/**
 * Pure payload-position engine for the programmatic Intruder (`intruder_attack`). Burp's own Intruder can't be
 * run via Montoya, so we generate the concrete requests ourselves and send them with `sendRequests`.
 *
 * Template marker syntax: Burp-style `§...§` pairs — each pair marks one insertion position; the text between
 * the markers is the base value (used for positions NOT being fuzzed, e.g. in sniper).
 *
 * Attack types:
 *  - **sniper**: one payload set; fuzz ONE position at a time (others keep their base value) → positions × payloads.
 *  - **pitchfork**: one payload set PER position; iterate sets in lockstep (min length) → one request per index.
 *  - **clusterbomb**: one payload set PER position; cartesian product of all sets.
 */
object PayloadEngine {

    /** Parsed template: literals interleaved with positions. literals.size == positionCount + 1. */
    data class Template(val literals: List<String>, val baseValues: List<String>) {
        val positionCount: Int get() = baseValues.size

        fun render(values: List<String>): String = buildString {
            for (i in literals.indices) {
                append(literals[i])
                if (i < values.size) append(values[i])
            }
        }
    }

    fun parse(template: String): Template {
        val parts = template.split('§')
        // n markers → n must be even → parts.size is odd. Otherwise markers are unbalanced: treat as no positions.
        if (parts.size % 2 == 0) return Template(listOf(template), emptyList())
        val literals = ArrayList<String>()
        val bases = ArrayList<String>()
        parts.forEachIndexed { i, s -> if (i % 2 == 0) literals.add(s) else bases.add(s) }
        return Template(literals, bases)
    }

    data class Generated(val request: String, val payloads: List<String>)

    fun generate(template: String, attackType: String, sets: List<List<String>>, maxRequests: Int): List<Generated> {
        val tpl = parse(template)
        if (tpl.positionCount == 0 || sets.isEmpty() || sets.all { it.isEmpty() }) return emptyList()
        val out = when (attackType.lowercase()) {
            "pitchfork" -> pitchfork(tpl, sets)
            "clusterbomb" -> clusterbomb(tpl, sets)
            else -> sniper(tpl, sets.first())
        }
        return if (out.size > maxRequests) out.take(maxRequests) else out
    }

    private fun sniper(tpl: Template, payloads: List<String>): List<Generated> {
        val result = ArrayList<Generated>()
        for (pos in 0 until tpl.positionCount) {
            for (p in payloads) {
                val values = tpl.baseValues.toMutableList()
                values[pos] = p
                result.add(Generated(tpl.render(values), listOf(p)))
            }
        }
        return result
    }

    private fun pitchfork(tpl: Template, sets: List<List<String>>): List<Generated> {
        val n = minOf(tpl.positionCount, sets.size)
        if (n == 0) return emptyList()
        val length = (0 until n).minOf { sets[it].size }
        val result = ArrayList<Generated>()
        for (k in 0 until length) {
            val values = tpl.baseValues.toMutableList()
            val chosen = ArrayList<String>()
            for (i in 0 until n) {
                values[i] = sets[i][k]; chosen.add(sets[i][k])
            }
            result.add(Generated(tpl.render(values), chosen))
        }
        return result
    }

    private fun clusterbomb(tpl: Template, sets: List<List<String>>): List<Generated> {
        val n = minOf(tpl.positionCount, sets.size)
        if (n == 0) return emptyList()
        var combos: List<List<String>> = listOf(emptyList())
        for (i in 0 until n) {
            val next = ArrayList<List<String>>()
            for (prefix in combos) for (p in sets[i]) next.add(prefix + p)
            combos = next
        }
        return combos.map { chosen ->
            val values = tpl.baseValues.toMutableList()
            chosen.forEachIndexed { i, p -> values[i] = p }
            Generated(tpl.render(values), chosen)
        }
    }
}
