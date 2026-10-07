package com.revoltsecurities.burpmcp.tools

import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult

/** Shared scope-confinement check + base-URL derivation for send/target tools. */
class ScopeGuard(private val scopeOnly: () -> Boolean, private val isInScope: (String) -> Boolean) {

    fun baseUrl(host: String, port: Int, secure: Boolean): String {
        val scheme = if (secure) "https" else "http"
        val portPart = if ((secure && port == 443) || (!secure && port == 80)) "" else ":$port"
        return "$scheme://$host$portPart/"
    }

    fun resolvePort(explicit: Int?, secure: Boolean): Int = explicit ?: if (secure) 443 else 80

    /** @return an error result if the target is out of scope while confinement is on, else null. */
    fun reject(host: String, port: Int, secure: Boolean): CallToolResult? {
        val url = baseUrl(host, port, secure)
        return if (scopeOnly() && !isInScope(url)) {
            Results.error("Blocked: $url is out of scope and scope-confinement is enabled.")
        } else {
            null
        }
    }
}
