# What agents can do with Revolt MCP Server

A capability map for AI agents / automation — framed the way a human pentester works. Every tool returns
**context-managed, paginated, structured** output, and mutating tools are gated (unsafe switch + scope).

> **Authorization:** only run active/mutating tools against targets you're authorized to test. Enable
> **scope confinement** so the agent can't touch out-of-scope hosts, and keep the **unsafe switch** off until
> you intend to let it send traffic / change state.

---

## 1. Recon & mapping (read-only — safe)
*Human: "what's the attack surface here?"*
- `get_site_map { host, pathPrefix, method, status, mimeType, search, minResponseLength, inScopeOnly }` —
  enumerate discovered endpoints as typed rows (paginated, keyset cursor).
- `get_proxy_http_history { host, method, status, mimeType, search, minResponseLength, maxResponseLength,
  responseContains }` — everything seen through the proxy; `responseContains` searches response bytes, not
  just the URL.
- `extract_js_endpoints { inScopeOnly }` — harvest URLs/paths from JS/HTML bodies, each with its source URL,
  message id and line number.
- `get_http_message { id, part, section, offset, length }` — read any request/response in byte-range slices;
  jump straight to an id (re-resolved live).
- `scope_check { url }` · `get_proxy_ws_history { host, direction, contains, search, minLength, maxLength }` ·
  `burp_version`.

**Chain:** `get_site_map(host=target)` → for each interesting row `get_http_message(id, section=meta)` →
pull bodies only where it matters.

## 2. Analysis (read-only, pure)
*Human: "what parameters does this take, and is anything reflected?"*
- `request_parse` / `response_parse` — structure a raw message.
- `params_extract` — list query/body params.
- `find_reflected` — count where input values echo in the response (XSS/reflection triage).
- `diff_requests` — diff two messages (e.g. authed vs unauthed).
- `url/base64/hash/jwt/decode_as` — decode tokens, JWTs, gzip/deflate bodies.

## 3. Manual testing & manipulation (mutating — gated)
*Human: "let me tweak this request and resend it."*
- `http_send { content, host, port, secure, httpMode }` — send a crafted raw request; returns a handle id,
  fetch the response with `get_http_message` (the agent's request/response workhorse).
- `repeater_create_tab` / `intruder_send` — hand a request to Repeater/Intruder for a human to continue.
- `cookie_jar_get` / `cookie_set` — inspect/seed Burp's cookie jar.
- `proxy_intercept { enabled }` — toggle intercept.

**Authenticated testing (do this FIRST).** `session_set { cookies, headers, hostOverride }` stores an auth
profile ONCE; it is auto-applied to every `http_send`/`http_send_analyze`/`http_send_compare`/`intruder_attack`/
`race_*` request and the `scan_audit_start` seed, and persists across context compaction/restarts. Each send
tool also takes per-call `cookie`/`headers` overrides. If a response comes back `status: 0` with an `error`, the
request got no response (bad Host/port/TLS or missing auth) — set a session and retry. For scanner-generated
traffic, also add a Burp session-handling rule → "Invoke a Burp extension" → Revolt MCP.

**Jump to any message:** `get_http_message { id }` re-resolves `ph:`/`sm:`/`iss:`/`ws:` ids live — go straight to
an id (even after context loss) without re-paginating; use `section=body` (or `full`) to read content.

**Chain (authz/IDOR):** `get_proxy_http_history(host)` → `get_http_message(id, part=request, section=full)` →
mutate an id/role → `http_send(...)` → `get_http_message(send_id)` → `diff_requests` the two responses.

## 4. Automated scanning (Burp Professional)
*Human: "crawl it, then audit for vulns."*
- `scan_crawl_start { seedUrls }` → `scan_task_status { taskId }` (poll) → `get_site_map` (new endpoints).
- `scan_audit_start { active, content, host }` → poll → `get_scanner_issues { severity, confidence, host }`.
- `get_scanner_issues` rows → `get_http_message(issue_id)` for evidence.
- `scan_report { taskId, format: html|xml, path }` — export (sandboxed to the reports dir).

**Chain (full auto):** `scan_crawl_start(seeds)` → poll → feed URLs → `scan_audit_start` → poll → triage
`get_scanner_issues` → `scan_report`.

## 5. Out-of-band / blind verification (Professional)
*Human: "is this SSRF/blind injection real?"*
- `collaborator_generate { customData }` — get a payload host (its secret key is auto-saved).
- inject the payload via `http_send`, then `collaborator_poll {}` (no args → polls ALL saved payloads, even
  after context loss) or `collaborator_poll { interactionId }` — DNS/HTTP/SMTP hits confirm OOB; HTTP evidence
  is fetchable via `get_http_message`.

## 6. Race conditions & high throughput
*Human: "fire 20 of these at once to break the state machine."*
- `race_parallel_send { content, host, count, mode: single_packet|last_byte|parallel }` — N identical requests
  fired together (HTTP/2 single-packet best-effort); responses grouped by outcome, a divergent group = likely win.
- `race_batch_send { requests[], host, mode }` — a group of different requests as one batch.

## 7. Findings, evidence & reporting
*Human: "log this finding with the request/response."*
- `issue_create { name, detail, severity, confidence, baseUrl, requestRaw, responseRaw }` — register a custom
  issue in Burp's site map (de-duplicated).
- `sitemap_add` — inject a discovered request/response into the site map.
- `scan_report` — HTML/XML report of issues.

## 8. External tool & workflow integration
*Human: "run nuclei and pull the findings in; ping the team."*
- `ingest_nuclei_findings { jsonl }` — parse a nuclei JSONL export → Burp issues (severity/target mapped, deduped).
- `webhook_notify { url, text, format }` — Slack/generic notify (SSRF-guarded).
- **Federation:** configure external MCP servers → their tools appear as `ext:<server>:<tool>` and the agent can
  call them through this one (results trust-boundary wrapped). E.g. drive a `nuclei-mcp`/`ffuf-mcp` alongside Burp.

## 9. Monitoring
- `events_poll { afterSeq, limit, kind: http|issue }` — stream new HTTP responses and scan issues forward from a
  cursor, so an agent can react to live traffic / findings instead of re-listing.

---

## End-to-end example: autonomous recon → audit → report
1. `scope_include(target)` *(mutating)* and enable scope confinement.
2. `scan_crawl_start(seedUrls=[target])` → poll `scan_task_status` until requestCount plateaus.
3. `get_site_map(host=target)` + `extract_js_endpoints` → collect endpoints.
4. `scan_audit_start(active=true, ...)` seeded from interesting requests → poll.
5. `get_scanner_issues(severity=medium)` → for each, `get_http_message(issue_id)` for evidence.
6. Verify blind issues with `collaborator_generate`/`collaborator_poll`; test races with `race_parallel_send`.
7. `scan_report(format=html)` and `webhook_notify` the summary.

## Safety model recap
- **Scope confinement** rejects out-of-scope sends/targets *before* any traffic.
- **Unsafe master switch** must be on for any mutating tool; **per-tool toggles** disable anything you don't want
  exposed; **Pro-only** tools hidden in Community. All enforced on the MCP wire path.
- **Bearer token + Origin checks**; binds loopback by default. Untrusted external output is trust-boundary wrapped.
