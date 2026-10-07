package com.revoltsecurities.burpmcp.mcp

import java.security.MessageDigest

/**
 * Pure bearer-token access decision for the HTTP transports, enforced in a Ktor interceptor that runs
 * before the MCP routes. Host/Origin (DNS-rebinding) defense is delegated to the SDK's `allowedHosts`/
 * `allowedOrigins` on the transport helpers; this gate only governs the bearer token.
 *
 * Contract:
 *  - If [requiredToken] is blank, the server is treated as unauthenticated-local (loopback only) and
 *    every request is allowed. Callers MUST only run tokenless on a loopback bind.
 *  - Otherwise the request must present `Authorization: Bearer <token>` with a constant-time match.
 */
class AuthGate(private val requiredToken: String) {

    /** @return null if allowed, else an HTTP status code + short message to respond with. */
    fun evaluate(authorizationHeader: String?): Denial? {
        if (requiredToken.isEmpty()) return null
        val presented = authorizationHeader
            ?.takeIf { it.startsWith(BEARER_PREFIX, ignoreCase = true) }
            ?.substring(BEARER_PREFIX.length)
            ?.trim()
            ?: return Denial(401, "Missing or malformed Authorization: Bearer header")
        return if (constantTimeEquals(presented, requiredToken)) {
            null
        } else {
            Denial(401, "Invalid bearer token")
        }
    }

    data class Denial(val status: Int, val message: String)

    private fun constantTimeEquals(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

    companion object {
        private const val BEARER_PREFIX = "Bearer "
    }
}
