# Revolt MCP Server v0.3.0 (beta)

Adds **native session auto-refresh** so a rotating/expiring token is maintained without any Burp macro.

- **New tools:** `session_login_set` / `session_login_get` / `session_login_clear` / `session_login_now`.
  Configure a login request + a regex that extracts the token from the login response, and where to put it
  (`Authorization` header, a cookie, custom template). When an **in-scope scan** sees a trigger status
  (default `401`/`403`), the extension replays the login, extracts a fresh token, and rotates it into the stored
  session profile automatically — subsequent scanner requests re-authenticate on their own. `session_login_now`
  forces a refresh on demand (use it when a send/intruder/race request returns 401/403).
- **Safe by design:** refresh only triggers on in-scope scanner traffic; the login request is sent with its own
  credentials (never the stale token); the login request is **encrypted at rest** and redacted by
  `session_login_get`; the token itself is never returned (only its length). One refresh in flight at a time, with
  a short debounce so a burst of 401s can't stampede logins.
- **UI:** the **Session** tab gains a "Session refresh (auto-login)" section (request, extract regex, target,
  token placement, trigger statuses) with **Save login** / **Test refresh now**.
- Token refresh now needs **no Burp UI** for the common bearer/cookie case; only very complex multi-step logins
  still benefit from a Burp login macro (documented).

150 unit tests. No API changes to existing tools.

---

# Revolt MCP Server v0.2.1 (beta)

Makes **authenticated scans work with no manual Burp setup**. The extension now registers a Burp HTTP handler
that injects the stored session profile into every **in-scope** request the scanner/crawler generates — so an
authenticated scan needs only `session_set` + a defined target scope, with **no session-handling rule to
configure**. Credentials are scope-gated and never attached to out-of-scope hosts (e.g. an off-site redirect the
scanner follows), so your token can't leak. The opt-in session-handling action is retained for pairing with a
Burp login macro when you need token **refresh** (re-login on 401), which is the only part still configured in
Burp's UI. Tool descriptions, README, playbooks and the Session tab updated accordingly. No API changes.

---

# Revolt MCP Server v0.2.0 (beta)

Field-feedback release: fixes 10 defects/gaps a live AI agent found driving v0.1.1 against real targets, so
authenticated, long-horizon testing works end-to-end.

## New — session injection (authenticated testing)

- **`session_set` / `session_get` / `session_clear`** — store a reusable auth profile (cookies, headers,
  optional Host override) ONCE. It is **auto-applied** to every `http_send`, `http_send_analyze`,
  `http_send_compare`, `intruder_attack`, `race_*` request and the audit seed, and persists (encrypted at rest)
  across agent context compaction and Burp restarts. All send tools also accept per-call `cookie`/`headers`
  overrides. A new **Session** tab in the UI views/edits/clears the profile.
- **Authenticated scans** — the audit seed is injected with the session profile, and a registered Burp
  session-handling action can inject it into scanner-generated requests (add a one-time Burp session-handling
  rule → "Invoke a Burp extension" → Revolt MCP). Montoya cannot create rules/macros, so that step stays in Burp.

## Fixes

- **No more silent "status 0 / length 0".** Sends now inject a `Host` header when missing and surface a real
  `error` ("no response: connection reset / TLS / timeout / wrong port or Host") instead of looking identical.
  `http_send_compare` returns a `note` + `errorA`/`errorB`; race/intruder report a `failed` count.
- **`get_http_message` is reliable.** Source ids (`ph:`/`sm:`/`iss:`/`ws:`) are **re-resolved live** from Burp
  even after LRU eviction or context loss — jump straight to an id without re-paginating. Clear errors for
  expired session ids. Accepts an optional `host` hint.
- **Richer history/site-map/WS filters.** Proxy history gains `minResponseLength`/`maxResponseLength` and
  `responseContains` (searches response bytes, not just the URL); site map gains `method`/`status`/
  `minResponseLength`; WebSocket history gains `direction`/`contains`/`search`/`minLength`/`maxLength`, and WS
  payloads are now fetchable via `get_http_message id=ws:<n>`.
- **`bcheck_import` reports real errors.** A broken BCheck (Burp returns `LOADED_WITH_ERRORS`) is now an error
  result with the parser messages in `errors`, and the tool documents the BCheck DSL shape.
- **`extract_js_endpoints` has source attribution** — each endpoint carries its source URL, message id, and line.
- **Collaborator keys survive compaction.** Secret keys are auto-persisted; `collaborator_poll` works with **no
  args** (polls all saved payloads) or by `interactionId` — the `secretKey` is no longer required.

## Quality

- 133 unit tests (incl. session injection, re-resolution, filters, key store, error surfacing). No API
  regressions; 2026.7-only APIs stay reflection-guarded; runs on Burp Professional 2025.4.4.

---

# Revolt MCP Server v0.1.1 (beta)

Adds **`project_info`** — a read-only tool returning the current Burp project's name and id — rounding out the
project/control tool surface (alongside `project_options_*`, `user_options_*`, `task_engine_state`,
`persistence_*`, and scope `include`/`exclude`/`check`). No other behavior changes.

---

# Revolt MCP Server v0.1.0 (beta)

First beta of **Revolt MCP Server for Burp Suite** — a Model Context Protocol (MCP) server, packaged
as a Burp extension, that exposes Burp to AI agents and automation with context-managed, paginated output and
safety gating.

## Highlights

- **56+ MCP tools** across HTTP/Repeater, Scanner & Crawler (Pro), Collaborator (Pro), a programmatic
  Intruder (sniper/pitchfork/clusterbomb with wordlist files), race conditions, proxy/site-map/issue browsing,
  cookies, scope, config/persistence, nuclei ingestion, webhooks, MCP federation and event streaming.
- **Selectable transport** — Streamable-HTTP (default) or HTTP+SSE.
- **Context-managed output** — keyset-cursor pagination, typed metadata rows (no raw-body dumps), byte-range
  body slicing with resumable markers, whole-response byte budget, binary omission.
- **Safety** — bearer-token auth, Origin/Host (DNS-rebinding) defense, unsafe-tools master switch, per-tool
  toggles, optional scope confinement — all enforced on the MCP wire path.
- **Works everywhere** — Claude Code, Claude Desktop, Cursor, OpenAI Codex, VS Code, SDKs, and plain HTTP
  scripts. See the README for per-client setup.
- **Modern in-Burp console** — dashboard, server controls, tool toggles, copy-paste client config.

## Quality

- 109 unit tests; passed a multi-pass adversarial security & correctness code review.
- Verified running on Burp Professional 2025.4.4 (compiled against Montoya API 2026.7; newer-only APIs are
  reflection-guarded and degrade gracefully).

## Install

1. Download `burp-mcp-server-0.1.0.jar` from the assets below.
2. Burp → **Extensions → Installed → Add → Java** → select the JAR.
3. Open the **Revolt MCP Server** tab → **Server** → Start. See the README for connecting agents.

## Requirements

- Burp Suite Community or Professional 2025.4+ (Professional unlocks Scanner & Collaborator tools).

## Known limitations

- stdio transport is served via an external bridge (`mcp-remote` / `supergateway`); no standalone bridge jar yet.
- MCP federation currently supports SSE external servers.
- Burp's own Intruder/Repeater cannot be *run/read* via the Montoya API (vendor limitation) — the extension
  provides equivalent programmatic tools instead.

## Verify

Check the JAR against `SHA256SUMS.txt` included in the assets.
