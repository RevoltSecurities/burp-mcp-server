# Revolt MCP Server v1.1.0

Hardening, correctness, and resilience release. Fixes found by adversarial code review and live‑agent field
testing, with no breaking changes to the tool surface.

## Security

- **DNS‑rebinding bypass fixed (high).** The loopback check used a `startsWith("127.")` prefix, so an
  attacker‑registered name like `127.0.0.1.evil.com` was treated as loopback and bypassed the tokenless
  server's Origin/Host gate. It now does a strict dotted‑quad parse of `127.0.0.0/8`.
- **Path‑sandbox symlink containment.** Wordlist / Bambda / report paths now resolve the real path and
  re‑assert containment, so a pre‑planted symlink inside a sandbox dir can't read or write outside it.
- **Federated tool descriptions sanitised.** An external MCP server's self‑declared tool description is now
  newline‑collapsed, fence‑neutralised and length‑bounded before entering the model's tool catalog.
- **Bambda repo fetch** rejects percent‑encoded traversal and caps response size.

## HTTP transport resilience (live‑agent fixes)

- **Degenerate‑response detection.** A failed transport that Burp surfaces as a synthetic `status 0` /empty
  response (e.g. an HTTP/2 negotiation the target won't complete) is now recognised as the failure it is:
  `ok=false`, `statusText="no response"`, a real `error`, and the correct `failed` count in intruder/race
  (previously such sends were reported `ok=true` / `failed=0`).
- **Automatic transport fallback.** With `httpMode=auto` (default), a send that returns no response now probes
  `http1`/`http2` and uses the one that works, reporting it in a new `httpModeUsed` field — so a target whose
  HTTP/2 Burp can't negotiate still succeeds over HTTP/1.1 instead of silently returning empty results. **Safety:**
  this re-send only happens for idempotent/safe methods (GET/HEAD/OPTIONS/TRACE); a mutating request (POST/PUT/…)
  is sent exactly once and, if it gets no response, reported as a failure with a hint to retry `httpMode=http1` —
  so a state-changing action is never executed more than once.
- **WAF/edge diagnostics.** Responses from known edge/WAF layers (`awselb`, `cloudfront`, `cloudflare`,
  `akamai`, …) are named in the result, and `http_send_compare` flags "all responses identical → likely a
  WAF/edge block, differential not meaningful" instead of returning unhelpful diff data.

## Correctness

- `cookie_set` expiry past 2038‑01‑19 and `events_poll afterSeq` beyond Int range no longer truncate to a
  wrong value (new 64‑bit `Args.long`).
- `task_engine_state` rejects an invalid state instead of silently resuming the engine.
- The event feed registers its handlers defensively, so a Community‑edition Scanner registration can't break
  extension init.
- Context layer: the page byte‑budget now reserves envelope + separator overhead (results can't exceed the
  configured budget), body slices snap the **start** offset to a UTF‑8 boundary, and keyset cursors validate
  their sort ordering, not just the filter set.

## Engine

- **True HTTP/1.1 last-byte race gate (clean-room).** `race_parallel_send`/`race_batch_send` with
  `mode=last_byte` now use a from-scratch last-byte-synchronization engine (`engine/Http1RaceGate`): one raw
  connection per request, every byte but the last written and flushed, a barrier until all connections are
  primed, then the held-back final byte released on all connections simultaneously (`TCP_NODELAY`, ALPN pinned
  to http/1.1). This is the public PortSwigger technique implemented on plain JDK sockets — no third-party
  code — for the tightest HTTP/1 race window. `mode=single_packet` continues to use Burp's HTTP/2
  single-packet (`sendRequests` + HTTP/2), which is what Turbo Intruder itself uses.
- **Managed request engine for fuzzing.** `intruder_attack` can route through Burp's
  `RequestExecutionEngine` (concurrency-limited, throttled, retried) when you pass `concurrency` and/or
  `throttleMs` — recommended for large or rate-sensitive targets. Reflection-guarded (2026.7+); falls back to
  the parallel batch on older Burp or if the engine is unavailable.

## Fixes

- **Race/intruder no longer report false "DIVERGED / likely race win".** `RaceAnalyzer` grouped on the whole
  response, so any per-request value (`Date`, `X-Request-Id`, `X-Runtime`, `Set-Cookie` nonces) made every
  response its own group. It now hashes the **body** only (status stays a separate key) and masks in-body
  UUIDs and ISO-8601 timestamps — while leaving numbers/amounts untouched so a genuine race signal (e.g. a
  differing balance) is still detected.

## Enhancements

- **Structured request building (prevents malformed requests).** The standard request tools — `http_send`,
  `http_send_analyze`, `http_send_compare`, `intruder_send`, `repeater_create_tab`, `sitemap_add`,
  `organizer_send` — now take **structured fields only**: `method`, `host`/`url`, `path`, `headers`, `body`
  + `bodyType` (`json`/`graphql`/`form`/`xml`/`soapxml`/`raw`), `httpVersion`. The server assembles a
  byte-correct request (Host always present, Content-Type per body shape, Content-Length computed), so a
  model can no longer hand-write a malformed raw request and scope resolution is unambiguous. The raw
  `content` parameter was **removed from these tools' schemas** (`http_send_compare` builds each side from
  `…A`/`…B` fields; each side is sent to its OWN resolved target and both are scope-checked, so a cross-origin
  A-vs-B compare routes correctly). Results echo the resolved `targetHost`.
- The **byte-exact** tools keep a raw request by design, now under an explicit name: `race_parallel_send`
  (`raw_request`), `race_batch_send` (`raw_requests`), and `intruder_attack` (`template` with `§` markers).
  These send your bytes verbatim because request smuggling / desync / single-packet races depend on exact
  bytes (e.g. a deliberately mismatched Content-Length).
- `organizer_items` now returns url/host/method/status/notes (not just id/status).
- Scanner issue `definitionId` uses the stable `typeIndex()`.

## Quality

- 228 unit tests (was 183); green on `./gradlew clean check shadowJar`.
- Still runs on Burp Suite **2025.4.4** (compiled against Montoya API 2026.7; newer‑only APIs reflection‑guarded).

---

# Revolt MCP Server v1.0.0

First public release. **Revolt MCP Server** is a Burp Suite extension that runs a Model Context Protocol (MCP)
server, exposing Burp to AI agents and deterministic scripts with **context‑managed, paginated output** and
**safety gating** on every tool call.

## Highlights

- **70+ MCP tools** across HTTP/Repeater, Scanner & Crawler (Pro), Collaborator (Pro), a programmatic Intruder
  (sniper/pitchfork/clusterbomb with wordlist files), race conditions, proxy history / site map / issues,
  cookies, scope, config & persistence, nuclei ingestion, webhooks, MCP federation, events, and Bambdas.
- **Selectable transport** — Streamable‑HTTP (default) or HTTP+SSE, chosen in the UI.
- **Context‑managed output** — keyset‑cursor pagination, typed metadata rows (never raw‑body dumps), byte‑range
  body slicing with resumable markers, a whole‑response byte budget, and binary omission. `get_http_message`
  fetches bytes on demand and re‑resolves `ph:/sm:/iss:/ws:` ids live, so you can jump straight to any message.
- **Authenticated testing** — a reusable session profile (cookies/headers/Host) set once and auto‑applied to
  every send/intruder/race request and to in‑scope scanner traffic, plus **native token auto‑refresh** (replay a
  login and rotate the token on 401/403 — no Burp macro). Stored encrypted; survives restarts and context loss.
- **Bambda tooling** — author/import Burp Bambdas (filters, columns, Repeater actions, match‑and‑replace, passive
  scan checks): `bambda_import` assembles a valid document from `name/function/location/source`, a paginated
  `bambda_script_doc` DSL reference, read‑only browse/fetch of the official PortSwigger/bambdas repo, and a
  sandboxed local `.bambda` library.
- **External results** — ingest nuclei findings inline or from a JSONL output file (sandboxed, scope‑gated,
  retargetable to an in‑scope host), SSRF‑guarded webhooks, and MCP federation (`ext:<server>:<tool>`).
- **Ergonomic targeting** — send tools take an optional `host`; when omitted it is derived from the request's
  `Host` header (or an absolute request‑line URL) and used for both the scope check and routing. A request that
  gets no response reports `ok=false` / `statusText="no response"` as an explicit error — never a confusing "0".
- **Safety first** — bearer‑token auth, Origin/Host (DNS‑rebinding) defense, an unsafe‑tools master switch,
  per‑tool toggles, and optional scope confinement — all enforced on the MCP wire path. File‑path tools are
  sandboxed; outbound fetches are host‑pinned or SSRF‑guarded.
- **Modern in‑Burp console** — dashboard, server controls, per‑tool toggles, a Session tab, and copy‑paste
  client config for Claude Code, Claude Desktop, Cursor, OpenAI Codex, VS Code, and any MCP/HTTP client.

## Quality

- 183 unit tests; passed multiple multi‑pass adversarial security & correctness code reviews plus live‑agent
  field testing.
- Runs on Burp Suite Professional/Community **2025.4.4** (compiled against Montoya API 2026.7; newer‑only APIs are
  reflection‑guarded and degrade gracefully). Professional unlocks Scanner, Collaborator, and Bambda scan checks.

## Install

1. Download `burp-mcp-server-1.0.0.jar` from the assets below.
2. Burp → **Extensions → Installed → Add → Java** → select the JAR.
3. Open the **Revolt MCP Server** tab → **Server** → Start, then connect your agent (see the README for per‑client setup).

## Verify

Check the JAR against `SHA256SUMS.txt` included in the assets.
