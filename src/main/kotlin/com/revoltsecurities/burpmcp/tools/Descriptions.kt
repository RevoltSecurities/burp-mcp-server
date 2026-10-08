package com.revoltsecurities.burpmcp.tools

/**
 * Reusable, precise parameter/description snippets shared across tools. Consistent, example-rich wording here
 * is the main defense against a model guessing wrong formats or calling the wrong companion tool.
 */
object Descriptions {

    const val RAW_REQUEST =
        "A COMPLETE raw HTTP request: request-line, then headers, then a blank line, then the optional body — " +
            "CRLF (\\r\\n) separated. Include a Host header. Send it verbatim (do NOT URL-encode the whole thing). " +
            "Example: \"POST /login HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Type: application/json\\r\\n\\r\\n{\\\"u\\\":\\\"a\\\"}\"."

    const val RAW_RESPONSE =
        "A COMPLETE raw HTTP response: status-line, headers, blank line, optional body (CRLF separated)."

    const val CURSOR =
        "Opaque pagination cursor. OMIT it on the first call. On later calls pass the EXACT nextCursor string " +
            "returned by the previous page. Never build or edit it; changing filters invalidates it."

    const val HOST_FILTER =
        "Filter by host — case-insensitive SUBSTRING match (e.g. \"example.com\" also matches \"api.example.com\"). Omit for all hosts."

    const val STATUS_FILTER =
        "Filter by HTTP status: an exact code (\"404\") or a class bucket (\"4xx\", \"5xx\"). Omit for any status."

    const val SEARCH_REGEX =
        "Optional regex matched against the URL (Java/Kotlin regex syntax). A malformed regex matches nothing."

    const val IN_SCOPE_ONLY =
        "Only include items in Burp's target scope. Defaults to true — set false to include everything."

    const val MESSAGE_ID =
        "A stable row id from a list tool: \"ph:<n>\" (get_proxy_http_history), \"sm:<hash>:<n>\" (get_site_map), " +
            "\"iss:<n>\" (get_scanner_issues), \"ws:<n>\" (get_proxy_ws_history), or \"send:<n>\"/\"race:<n>\"/" +
            "\"collab:<n>\" from send/race/collaborator tools. Source ids (ph/sm/iss/ws) are re-resolved live, so you " +
            "can jump straight to one without re-paginating; session ids (send/race/collab) expire — re-run that tool."

    const val TARGET_HOST = "Target hostname, e.g. \"example.com\" (no scheme, no path)."
    const val TARGET_PORT = "Target port. Defaults to 443 when secure, else 80."
    const val TARGET_SECURE = "Use TLS/HTTPS. Defaults to true."

    const val TARGET_HOST_OPT =
        "Target hostname, e.g. \"example.com\" (no scheme/path). OPTIONAL: if omitted it is taken from the " +
            "request's Host header (or an absolute request-line URL) — that derived host is what the scope check " +
            "and routing use. Pass it only to override the Host header."
    const val TARGET_PORT_OPT =
        "Target port. Optional: derived from the Host header's \":port\" or an absolute URL; else 443 (secure) / 80."
    const val TARGET_SECURE_OPT =
        "Use TLS/HTTPS. Optional: derived from an absolute https/http request-line URL; otherwise defaults to true."

    const val NO_TARGET_HOST =
        "No target host: include a Host header in the request (or pass 'host'). The scope check and routing use that host."

    const val SESSION_COOKIE =
        "Optional Cookie header value to inject/merge for THIS request only, e.g. \"session=abc; csrf=xyz\". " +
            "Merged over (and overriding) the stored session profile. To avoid repeating it on every call, set it " +
            "once with session_set and omit here."
    const val SESSION_HEADERS =
        "Optional extra request headers to inject for THIS request only, each as a \"Name: value\" string " +
            "(e.g. [\"Authorization: Bearer eyJ...\", \"X-Api-Key: k\"]). Added or replacing same-named headers, " +
            "overriding the stored session profile. Prefer session_set for persistent auth."
}
