package com.revoltsecurities.burpmcp.tools

/**
 * Resolves the connection target (host/port/secure) for send-style tools. An explicit `host`/`port`/`secure`
 * argument always wins; anything omitted is derived from the raw request's `Host` header / absolute request-line
 * (see [HttpParse.hostTarget]). This is what lets an agent pass a full raw request and NOT duplicate the host —
 * the same derived host is used for the scope gate and for routing. Montoya-free → unit-tested.
 */
object TargetArgs {

    data class Target(val host: String, val port: Int, val secure: Boolean)

    /** Null when no host can be determined (no `host` arg AND no Host header / absolute URL in [content]). */
    fun resolve(args: Args, content: String?): Target? {
        val explicitHost = args.str("host")
        // Only derive from the request when the host is NOT explicitly overridden — an override points at a
        // different server, so its port/scheme must come from the args/defaults, not the request's own Host.
        val derived = if (explicitHost == null) content?.let { HttpParse.hostTarget(it) } else null
        val host = explicitHost ?: derived?.host ?: return null
        val port = args.int("port") ?: derived?.port
        // secure: explicit arg → absolute-URL scheme → inferred from a derived port (80=http, 443=https) → default true.
        val secure = args.bool("secure") ?: derived?.secure ?: when (port) {
            80 -> false
            443 -> true
            else -> true
        }
        return Target(host, port ?: if (secure) 443 else 80, secure)
    }
}
