package com.revoltsecurities.burpmcp.tools

/**
 * Curated, offline reference for the Burp Bambda DSL, served by the `bambda_script_doc` tool as topic → content.
 * Distilled from the official PortSwigger/bambdas repo so an agent can learn the exact document format, the
 * function/location enums, the in-scope variables/helpers, and per-function body contracts without guessing.
 * Live example scripts come from `bambda_repo_list`/`bambda_fetch`.
 */
object BambdaDocs {

    data class Topic(val key: String, val blurb: String, val content: String)

    val topics: List<Topic> = listOf(
        Topic(
            "overview",
            "What Bambdas are and how to use them here.",
            """
            # Bambdas

            A Bambda is a small Java snippet Burp runs in a specific context (filter proxy rows, add a custom
            column, run a Repeater action, match-and-replace, or a passive scan check). Use them for autonomous
            triage and custom detections.

            Workflow with this server:
            1. `bambda_script_doc topic=format` — learn the document shape.
            2. `bambda_repo_list` / `bambda_fetch path=...` — browse/copy official examples (PortSwigger/bambdas).
            3. `bambda_import` — load one into Burp (pass a full `document`, or structured name/function/location/source).
            4. `bambda_save` / `bambda_list` / `bambda_get` / `bambda_delete` — keep your own `.bambda` library.

            Table filters (VIEW_FILTER) work in Burp Community + Professional; the other function types need
            Professional.
            """.trimIndent(),
        ),
        Topic(
            "format",
            "The exact .bambda document structure (header + source block).",
            """
            # Document format

            A `.bambda` document is a small header followed by a `source:` block holding the Java body. Burp's
            import needs the WHOLE document — a bare snippet fails with "function required / location required".

            ```
            id: <uuid>                 # optional; bambda_import generates one if you omit the header
            name: <display name>
            function: <FUNCTION_ENUM>   # see topic=functions
            location: <LOCATION_ENUM>   # see topic=locations
            source: |+
              /** Short description. @author you **/
              <Java body indented 2 spaces>
            ```

            Easiest path: call `bambda_import` with `name`, `function`, `location`, and `source` (just the Java
            body) — the server assembles a valid document for you. Do NOT add `import` statements; the Burp
            Montoya API classes are already in scope.
            """.trimIndent(),
        ),
        Topic(
            "functions",
            "The function: enum values and what each body must return/do.",
            """
            # function: values (what the body returns)

            - VIEW_FILTER — return a `boolean` (true = keep the row). For table filtering.
            - CUSTOM_COLUMN — return a value (usually `String`) shown in the column cell.
            - CUSTOM_ACTION — imperative statements with side effects (send requests, set editor panes, log). No
              required return. Runs from Repeater.
            - MATCH_AND_REPLACE_REQUEST — return a (possibly modified) `HttpRequest`.
            - MATCH_AND_REPLACE_RESPONSE — return a (possibly modified) `HttpResponse`.
            - SCAN_CHECK_PASSIVE_PER_REQUEST — return an `AuditResult` (wrapping zero or more `AuditIssue`s).
            """.trimIndent(),
        ),
        Topic(
            "locations",
            "The location: enum values (where the Bambda runs).",
            """
            # location: values (the Burp context)

            - PROXY_HTTP_HISTORY — Proxy HTTP history (filters, columns, match-and-replace).
            - PROXY_WEBSOCKET — Proxy WebSockets history (uses `message`, not `requestResponse`).
            - REPEATER — Repeater custom actions (CUSTOM_ACTION; `httpEditor` available).
            - SCANNER — passive scan checks (SCAN_CHECK_PASSIVE_PER_REQUEST).
            - LOGGER — Logger view filters/columns.
            - SITE_MAP — Site map filters.

            Common pairings: VIEW_FILTER+PROXY_HTTP_HISTORY, CUSTOM_COLUMN+PROXY_HTTP_HISTORY,
            CUSTOM_ACTION+REPEATER, MATCH_AND_REPLACE_REQUEST+PROXY_HTTP_HISTORY, SCAN_CHECK_PASSIVE_PER_REQUEST+SCANNER.
            """.trimIndent(),
        ),
        Topic(
            "variables",
            "Objects in scope inside the body, by context.",
            """
            # In-scope variables

            HTTP contexts (filter/column/action/match-replace/scan): `requestResponse`
            - `requestResponse.hasResponse()`, `.request()`, `.response()`, `.finalRequest()`, `.annotations()`
            - request: `.url()`, `.method()`, `.body()`, `.bodyToString()`, `.hasHeader(name)`,
              `.headerValue(name)`, `.hasParameter(name, type)`, `.parameter(name, type).value()`,
              `.httpVersion()`, `.withAddedHeader(name, value)`, `.toByteArray()`
            - response: `.statusCode()`, `.bodyToString()`, `.hasHeader(name)`, `.headerValue(name)`, `.mimeType()`

            WebSocket context (PROXY_WEBSOCKET): `message`
            - `message.payload()`, `.direction()`, `.annotations()` (e.g. `.annotations().hasNotes()`)

            Repeater CUSTOM_ACTION also has: `httpEditor`
            - `httpEditor.requestPane()`, `httpEditor.responsePane().set(bytes)`
            """.trimIndent(),
        ),
        Topic(
            "helpers",
            "API handles available inside the body.",
            """
            # Helpers / API handles

            - `utilities()` (or bare `utilities`): `.base64Utils().decode(str, Base64DecodingOptions.URL)`,
              `.cryptoUtils().generateDigest(bytes, DigestAlgorithm.SHA_256)`, `.byteUtils().convertToString(bytes)`
            - `api()`: `.http().sendRequest(request, HttpMode.HTTP_2)` — issue new requests
            - `logging()`: `.logToOutput(msg)`, `.logToError(msg)`
            - Standard JDK is available directly: `Pattern`, `Matcher`, `List.of(...)`, `StringBuilder`, `HexFormat`.
            """.trimIndent(),
        ),
        Topic(
            "enums",
            "Common Montoya enums usable in the body.",
            """
            # Common enums (no import needed)

            - HttpParameterType: URL, BODY, COOKIE, ...
            - Base64DecodingOptions: URL, STANDARD
            - HttpMode: HTTP_1, HTTP_2, AUTO
            - DigestAlgorithm: SHA_256, SHA_1, MD5, ...
            - AuditIssueSeverity: HIGH, MEDIUM, LOW, INFORMATION
            - AuditIssueConfidence: CERTAIN, FIRM, TENTATIVE
            """.trimIndent(),
        ),
        Topic(
            "writing-filter",
            "Example: a VIEW_FILTER (boolean) Bambda.",
            """
            # VIEW_FILTER example (keep rows whose response hints at a SQL error)

            function: VIEW_FILTER, location: PROXY_HTTP_HISTORY. Body returns boolean:
            ```
            if (!requestResponse.hasResponse()) { return false; }
            var response = requestResponse.response();
            if (response.statusCode() < 400) { return false; }
            String body = response.bodyToString();
            return body.contains("You have an error in your SQL syntax")
                || body.contains("ORA-01756") || body.contains("SQLSTATE");
            ```
            """.trimIndent(),
        ),
        Topic(
            "writing-column",
            "Example: a CUSTOM_COLUMN (returns a value) Bambda.",
            """
            # CUSTOM_COLUMN example (JWT alg from a session cookie)

            function: CUSTOM_COLUMN, location: PROXY_HTTP_HISTORY. Body returns the cell value:
            ```
            if (!requestResponse.finalRequest().hasParameter("session", HttpParameterType.COOKIE)) { return ""; }
            var v = requestResponse.finalRequest().parameter("session", HttpParameterType.COOKIE).value();
            var parts = v.split("\\.");
            if (parts.length != 3) { return ""; }
            var header = utilities().base64Utils().decode(parts[0], Base64DecodingOptions.URL).toString();
            var m = Pattern.compile(".+?\"alg\":\"(\\w+)\".+").matcher(header);
            return m.matches() ? m.group(1) : "";
            ```
            """.trimIndent(),
        ),
        Topic(
            "writing-action",
            "Example: a CUSTOM_ACTION (imperative, Repeater) Bambda.",
            """
            # CUSTOM_ACTION example (retry until the status changes — race probing)

            function: CUSTOM_ACTION, location: REPEATER. Body is statements (no return):
            ```
            var mode = requestResponse.request().httpVersion().equals("HTTP/2") ? HttpMode.HTTP_2 : HttpMode.HTTP_1;
            var baseline = requestResponse.response().statusCode();
            for (int i = 0; i < 20; i++) {
                var attack = api().http().sendRequest(requestResponse.request(), mode);
                if (attack.response().statusCode() != baseline) {
                    httpEditor.responsePane().set(attack.response().toByteArray());
                    break;
                }
            }
            ```
            """.trimIndent(),
        ),
        Topic(
            "writing-match-replace",
            "Example: a MATCH_AND_REPLACE_REQUEST Bambda.",
            """
            # MATCH_AND_REPLACE_REQUEST example (sign the request body)

            function: MATCH_AND_REPLACE_REQUEST, location: PROXY_HTTP_HISTORY. Body returns an HttpRequest:
            ```
            var digest = utilities().cryptoUtils().generateDigest(
                requestResponse.request().body(), DigestAlgorithm.SHA_256);
            var sig = HexFormat.of().formatHex(digest.getBytes());
            return requestResponse.request().withAddedHeader("Content-Sha256", sig);
            ```
            """.trimIndent(),
        ),
        Topic(
            "writing-scan-check",
            "Example: a SCAN_CHECK_PASSIVE_PER_REQUEST Bambda.",
            """
            # SCAN_CHECK_PASSIVE_PER_REQUEST example (flag a missing CSP header)

            function: SCAN_CHECK_PASSIVE_PER_REQUEST, location: SCANNER. Body returns an AuditResult:
            ```
            if (!requestResponse.hasResponse()) { return AuditResult.auditResult(); }
            if (!requestResponse.response().hasHeader("Content-Security-Policy")) {
                return AuditResult.auditResult(AuditIssue.auditIssue(
                    "Content Security Policy header missing",
                    "The response lacks a Content-Security-Policy header.",
                    "Set a restrictive Content-Security-Policy.",
                    requestResponse.request().url(),
                    AuditIssueSeverity.LOW, AuditIssueConfidence.FIRM,
                    null, null, AuditIssueSeverity.LOW, requestResponse));
            }
            return AuditResult.auditResult();
            ```
            """.trimIndent(),
        ),
        Topic(
            "import",
            "How to import a Bambda through this server.",
            """
            # Importing

            `bambda_import` accepts EITHER:
            - `document`: a full `.bambda` text (e.g. from `bambda_fetch`), or
            - `name` + `function` + `location` + `source` (the Java body) — the server assembles the document.

            The result reports `ok`; if false, read `errors` (Burp's parser messages) and fix the body. A broken
            script still "loads with errors" in Burp, so always check `ok`.
            """.trimIndent(),
        ),
        Topic(
            "attribution",
            "Licensing for scripts fetched from the official repo.",
            """
            # Attribution

            Scripts from PortSwigger/bambdas are LGPL-3.0 and carry a per-file `@author` in their header comment.
            Keep both the license notice and the author when reusing or redistributing a fetched script.
            """.trimIndent(),
        ),
    )

    private val byKey = topics.associateBy { it.key }

    fun topic(key: String): Topic? = byKey[key]

    /** One-line index of all topics for the no-argument call. */
    fun index(): String = buildString {
        appendLine("Bambda DSL reference — call bambda_script_doc topic=<key> for any of:")
        topics.forEach { appendLine("- ${it.key}: ${it.blurb}") }
    }
}
