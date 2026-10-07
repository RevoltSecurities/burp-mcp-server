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
