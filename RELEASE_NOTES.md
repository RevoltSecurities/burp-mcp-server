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
