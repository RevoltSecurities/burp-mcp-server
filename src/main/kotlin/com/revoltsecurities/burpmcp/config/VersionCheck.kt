package com.revoltsecurities.burpmcp.config

/**
 * Pure semantic-version comparison for the in-dashboard update check. Parses `vX.Y.Z` (leading `v` optional,
 * any `-pre`/`+build` suffix ignored, missing components treated as 0) and tells whether a release tag is newer
 * than the running build. Montoya-free → unit-tested.
 */
object VersionCheck {

    data class Ver(val parts: List<Int>) : Comparable<Ver> {
        override fun compareTo(other: Ver): Int {
            for (i in 0 until maxOf(parts.size, other.parts.size)) {
                val d = parts.getOrElse(i) { 0 } - other.parts.getOrElse(i) { 0 }
                if (d != 0) return d
            }
            return 0
        }
    }

    fun parse(raw: String): Ver? {
        val core = raw.trim().trimStart('v', 'V').substringBefore('-').substringBefore('+')
        if (core.isEmpty()) return null
        val nums = core.split('.').map { it.trim().toIntOrNull() ?: return null }
        return Ver(nums)
    }

    /** True when [latest] is a strictly newer version than [current] (both unparseable/equal → false). */
    fun isNewer(current: String, latest: String): Boolean {
        val c = parse(current) ?: return false
        val l = parse(latest) ?: return false
        return l > c
    }
}
