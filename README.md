<div align="center">

<img src="docs/assets/logo.svg" alt="Revolt MCP Server" width="128" height="128">

# Revolt MCP Server for Burp Suite

**Drive Burp Suite from AI agents and automation — safely, with context-managed output.**

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server, packaged as a Burp Suite
extension, that exposes Burp's capabilities (HTTP, Scanner, Crawler, Collaborator, a programmatic
Intruder, race conditions, proxy/site-map/issues, MCP federation, and more) to any MCP client — Claude
Code, Claude Desktop, Cursor, OpenAI Codex, VS Code, custom SDK scripts, or deterministic scanners.

![Burp](https://img.shields.io/badge/Burp%20Suite-2025.4%2B-E8743B)
![Kotlin](https://img.shields.io/badge/Kotlin-2.4.20-7F52FF)
![JVM](https://img.shields.io/badge/JVM-21-ED8B00)
![MCP](https://img.shields.io/badge/MCP-streamable--http%20%7C%20sse-2ea44f)
![Tools](https://img.shields.io/badge/tools-56%2B-informational)
![License](https://img.shields.io/badge/license-MIT-blue)
![Status](https://img.shields.io/badge/status-beta-yellow)

</div>

---

## Table of contents

- [Why](#why)
- [Features](#features)
- [Requirements](#requirements)
- [Install](#install)
- [Run the server](#run-the-server)
- [Connect an agent](#connect-an-agent)
  - [Claude Code](#claude-code-cli)
  - [Claude Desktop](#claude-desktop)
  - [Cursor](#cursor)
  - [OpenAI Codex CLI](#openai-codex-cli)
  - [VS Code (Copilot agent mode)](#vs-code--copilot-agent-mode)
  - [Windsurf / Cline / Continue / other MCP clients](#other-mcp-clients)
  - [Python / TypeScript SDK & scripts](#python--typescript-sdk--scripts)
- [Transports](#transports)
- [Security model](#security-model)
- [Tool catalog](#tool-catalog)
- [Context-managed output](#context-managed-output)
- [Examples](#examples)
- [Configuration reference](#configuration-reference)
- [Compatibility](#compatibility)
- [Build from source](#build-from-source)
- [Status & roadmap](#status--roadmap)
- [License](#license)

---

## Why

AI agents are great at reasoning about web-app security but terrible at handling Burp's raw data volume —
a single proxy-history dump or scan-issue list blows the model's context window. Revolt MCP Server solves
this: **every list is paginated with cursors and returns typed metadata rows (never raw bodies)**, and
large request/response bodies are fetched on demand in **resumable byte-range slices** under a strict
budget. The result is an agent (or a deterministic script) that can run a full workflow —
recon → analysis → manual testing → automated scan → OOB verification → race conditions → reporting —
without ever drowning in tokens, and with mutating actions gated behind an explicit safety switch.

## Features

- **59+ MCP tools** spanning HTTP/Repeater, Scanner & Crawler (Pro), Collaborator (Pro), a programmatic
  Intruder (sniper/pitchfork/clusterbomb with wordlist files), race conditions, proxy/site-map/issue
  browsing, cookies, scope, config/persistence, nuclei ingestion, webhooks, MCP federation and events.
- **Authenticated testing** — a reusable session profile (cookies/headers/Host) set once and auto-applied to
  every send/intruder/race request and scans; survives context compaction and restarts (encrypted at rest).
- **Selectable transport** — Streamable-HTTP (default) or HTTP+SSE, chosen in the UI.
- **Context-managed output** — keyset-cursor pagination, typed rows, byte-range body slicing with resumable
  markers, whole-response byte budget, binary omission.
- **Safety first** — bearer-token auth, Origin/Host (DNS-rebinding) defense, an **unsafe-tools master
  switch**, **per-tool toggles**, and optional **scope confinement** — all enforced on the MCP wire path.
- **Works with any MCP client** and with plain HTTP scripts (deterministic, no LLM required).
- **Modern in-Burp console** — dashboard, server controls, tool toggles, copy-paste client config.

## Requirements

- **Burp Suite** Community or **Professional** 2025.4+ (Professional unlocks Scanner & Collaborator tools).
- **JDK 21** (only needed to *build* from source; the released JAR runs on Burp's bundled JRE).
- An MCP client (optional) such as Claude Code, Claude Desktop, Cursor, Codex, or VS Code; and
  [Node.js](https://nodejs.org) 18+ if a client needs the `mcp-remote` bridge.

## Install

1. Download `burp-mcp-server-<version>.jar` from the [Releases](../../releases) page (or
   [build it](#build-from-source)).
2. In Burp: **Extensions → Installed → Add**.
3. Extension type: **Java** → select the JAR → **Next**.
4. A **Revolt MCP Server** tab appears. (Check the extension's **Output** for the startup log.)

## Run the server

1. Open the **Revolt MCP Server** tab → **Server**.
2. Set **Transport** `STREAMABLE_HTTP`, **Host** `127.0.0.1`, **Port** `9876`.
3. **Bearer token:**
   - **Local testing:** leave it blank — the server binds loopback-only and accepts unauthenticated local
     clients.
   - **Shared/remote or just safer:** click **Generate** and copy the token. *(A non-loopback bind without a
     token is refused.)*
4. Optionally tick **Allow mutating tools** (enables send/scan/intruder/cookie/options tools — off by
   default = read-only & safe) and **Confine tools to in-scope targets only**.
5. **Save settings → Start.** Status should read **RUNNING**.
6. The **Connect** sub-tab shows the exact endpoint + ready-to-paste client config.

> **Endpoint:** `http://<host>:<port>/mcp` (Streamable-HTTP) or `http://<host>:<port>/sse` (SSE).

## Connect an agent

Replace `<TOKEN>` with your bearer token, or omit the `Authorization` header entirely if you left the token
blank for local use.

### Claude Code (CLI)

```bash
# Streamable-HTTP (default transport)
claude mcp add --transport http revolt-burp http://127.0.0.1:9876/mcp \
  --header "Authorization: Bearer <TOKEN>"

# verify
claude mcp list
```
Then in a session: `List the proxy HTTP history for host example.com` — Claude Code will call the tools.

### Claude Desktop

Claude Desktop speaks MCP over stdio, so bridge it with [`mcp-remote`](https://www.npmjs.com/package/mcp-remote).
Edit `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "revolt-burp": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote", "http://127.0.0.1:9876/mcp",
        "--header", "Authorization: Bearer <TOKEN>"
      ]
    }
  }
}
```
Restart Claude Desktop; the Revolt Burp tools appear in the tools menu. *(For the SSE transport use
`--sse` with `supergateway` instead: `npx -y supergateway --sse http://127.0.0.1:9876/sse`.)*

### Cursor

Create `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project):

```json
{
  "mcpServers": {
    "revolt-burp": {
      "url": "http://127.0.0.1:9876/mcp",
      "headers": { "Authorization": "Bearer <TOKEN>" }
    }
  }
}
```
Reload Cursor → **Settings → MCP** should show `revolt-burp` connected.

### OpenAI Codex CLI

Codex launches MCP servers as subprocesses, so bridge the HTTP endpoint with `mcp-remote`. Edit
`~/.codex/config.toml`:

```toml
[mcp_servers.revolt-burp]
command = "npx"
args = ["-y", "mcp-remote", "http://127.0.0.1:9876/mcp", "--header", "Authorization: Bearer <TOKEN>"]
```
Run `codex` and the tools are available to the agent.

### VS Code (Copilot agent mode)

Create `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "revolt-burp": {
      "type": "http",
      "url": "http://127.0.0.1:9876/mcp",
      "headers": { "Authorization": "Bearer <TOKEN>" }
    }
  }
}
```
Open the Copilot **Agent** view → the `revolt-burp` tools are selectable.

### Other MCP clients

**Windsurf, Cline, Continue, LibreChat, 5ire, Zed,** and most others accept either a direct HTTP/SSE URL or
an `mcp-remote` stdio bridge — use the Cursor-style `url + headers` block if the client supports HTTP, or the
Claude-Desktop-style `command/args` block if it only supports stdio. The server is standard MCP, so anything
that speaks the protocol works.

### Python / TypeScript SDK & scripts

Any SDK connects to the same endpoint — see [`examples/`](examples/) for runnable scripts:

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("http://127.0.0.1:9876/mcp",
                                 headers={"Authorization": "Bearer <TOKEN>"}) as (r, w, _):
    async with ClientSession(r, w) as s:
        await s.initialize()
        page = await s.call_tool("get_site_map", {"host": "example.com", "limit": 50})
```

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const t = new StreamableHTTPClientTransport(new URL("http://127.0.0.1:9876/mcp"),
  { requestInit: { headers: { Authorization: "Bearer <TOKEN>" } } });
const c = new Client({ name: "auto", version: "1.0" }); await c.connect(t);
await c.callTool({ name: "get_site_map", arguments: { host: "example.com", limit: 50 } });
```

A **zero-dependency** example (`examples/sitemap_dump_stdlib.py`) uses only the Python stdlib, so deterministic
scanners can integrate without any SDK.

## Transports

| Transport | Endpoint | Use it for |
|---|---|---|
| **Streamable-HTTP** (default) | `/mcp` | Claude Code, Cursor, VS Code, SDKs, curl — the current standard. |
| **HTTP + SSE** | `/sse` (+ `/message`) | Clients that only speak the older SSE transport (via `supergateway`). |

Switch transport on the **Server** tab; the **Connect** tab regenerates the matching client config.

## Security model

- **Bind:** `127.0.0.1` by default. Binding a non-loopback interface **without** a bearer token is refused.
- **Auth:** bearer token on HTTP transports, constant-time compared. Blank token ⇒ loopback-only,
  unauthenticated (for convenience during local testing).
- **DNS-rebinding/CSRF:** exact-host `Origin` validation; for the tokenless local server the `Host` header
  must also be loopback.
- **Gating (enforced on the wire path):** mutating tools require the **unsafe master switch**; **per-tool
  toggles** disable anything you don't want exposed; **Pro-only** tools are hidden in Community; optional
  **scope confinement** rejects out-of-scope sends, scans and targets *before* any traffic.
- **Secrets:** bearer + external-server tokens encrypted at rest (AES-256-GCM); cookie values redacted unless
  explicitly revealed under the unsafe switch; webhook URLs are SSRF-guarded.
- **Untrusted data:** federated/external tool output is trust-boundary wrapped.

> ⚠️ **Only test targets you are authorized to test.** Keep the unsafe switch off and scope confinement on
> unless you intend otherwise.

## Tool catalog

<details>
<summary><b>59+ tools by domain (click to expand)</b></summary>

- **Status/Config:** `status`, `burp_version`, `project_options_get/set`, `user_options_get/set`,
  `task_engine_state`, `persistence_get/set/keys`, `bambda_import`
- **Utilities:** `url_encode/decode`, `base64_encode/decode`, `hash_compute`, `jwt_decode`, `decode_as`
- **Requests & analysis:** `http_send`, `http_send_analyze`, `http_send_compare`, `request_parse`,
  `response_parse`, `params_extract`, `find_reflected`, `diff_requests`, `repeater_create_tab`, `intruder_send`
- **Session / auth:** `session_set`, `session_get`, `session_clear` (reusable cookies/headers auto-applied to all send tools)
- **History / Site map / Scope:** `get_proxy_http_history`, `get_proxy_ws_history`, `get_site_map`,
  `scope_check`, `scope_include`, `scope_exclude`, `sitemap_add`
- **Output:** `get_http_message` (byte-range slices)
- **Scanner & recon (Pro):** `scan_crawl_start`, `scan_audit_start`, `scan_task_status/list/delete`,
  `scan_report`, `get_scanner_issues`, `issue_create`, `extract_js_endpoints`, `bcheck_import`
- **Collaborator (Pro):** `collaborator_generate`, `collaborator_poll`
- **Attack:** `intruder_attack` (sniper/pitchfork/clusterbomb + wordlist files), `list_wordlists`,
  `race_parallel_send`, `race_batch_send`
- **Cookies / Proxy / WebSocket / Organizer:** `cookie_jar_get`, `cookie_set`, `proxy_intercept`,
  `ws_send`, `organizer_send`, `organizer_items`
- **Integrations:** `ingest_nuclei_findings`, `webhook_notify`, federated `ext:<server>:<tool>`
- **Events:** `events_poll`

</details>

See **[docs/AGENT_PLAYBOOKS.md](docs/AGENT_PLAYBOOKS.md)** for how an agent chains these like a human pentester.

## Authenticated testing

Set an auth/session profile **once** and every send reuses it — no re-pasting cookies on each call, and it
survives agent context compaction and Burp restarts (stored encrypted):

```jsonc
// session_set
{ "cookies": ["session=abc", "csrf=xyz"], "headers": ["Authorization: Bearer eyJ..."] }
```

The profile is auto-applied to `http_send`, `http_send_analyze`, `http_send_compare`, `intruder_attack`,
`race_*` and the `scan_audit_start` seed; every send tool also takes per-call `cookie`/`headers` overrides. View
or edit it on the **Session** tab. For **scanner-generated** requests (Burp builds those itself, and the Montoya
API can't attach auth to them), also add one Burp session-handling rule whose action is **"Invoke a Burp
extension" → Revolt MCP**, plus a Burp login macro if you need token refresh on 401.

If a send comes back with `status: 0` and an `error`, the request got no response (bad Host/port/TLS or missing
auth) — add a session and retry; the tools say so explicitly rather than looking "identical".

## Context-managed output

List tools return a **page envelope** — typed rows + an opaque keyset `nextCursor` + `hasMore`/`totalCount`
and a resumable `truncation` note — and **never embed bodies**. Each row carries a stable `id`; fetch bytes on
demand with `get_http_message` (`section=meta|headers|body|full`, `offset`/`length`), which slices large bodies
and omits binary content. The whole response is capped to a byte budget (~25k tokens). Default filters
(`inScopeOnly=true`, `limit=50`, server cap 100) keep an agent from ever pulling "everything" by accident.

## Examples

| Script | What it does |
|---|---|
| [`examples/sitemap_dump.py`](examples/sitemap_dump.py) | List a host's site map (paginated) and dump each endpoint's request/response (official MCP SDK). |
| [`examples/sitemap_dump_stdlib.py`](examples/sitemap_dump_stdlib.py) | Same, zero dependencies. |
| [`examples/intruder_attack.py`](examples/intruder_attack.py) | Run the programmatic Intruder (sniper/pitchfork/clusterbomb, wordlist files). |

## Configuration reference

Settings live on the **Server**/**Tools**/**Session** tabs and persist in Burp's project preferences (secrets encrypted).

| Setting | Default | Meaning |
|---|---|---|
| Transport | `STREAMABLE_HTTP` | `STREAMABLE_HTTP` or `SSE`. |
| Host / Port | `127.0.0.1` / `9876` | Bind address. |
| Bearer token | *(blank)* | Required for non-loopback binds; sent as `Authorization: Bearer`. |
| Allow mutating tools | off | Master switch for tools that send traffic / change state. |
| Confine to scope | off | Reject out-of-scope sends/scans/targets. |
| Per-tool toggles | per default | Enable/disable individual tools (restart server to apply). |
| Wordlists dir | `~/.revolt-mcp/wordlists` | Where `intruder_attack` reads payload files (`list_wordlists`). |

## Compatibility

Compiled against Montoya API 2026.7; verified on Burp **Professional 2025.4.4**. 2026.7-only APIs (the managed
request engine, Organizer listing) are reflection-detected and degrade gracefully, so the extension runs on
older Burp. Scanner/Collaborator tools require **Professional**.

## Build from source

```bash
git clone https://github.com/RevoltSecurities/burp-mcp-server.git
cd burp-mcp-server
JAVA_HOME=/path/to/jdk-21 ./gradlew clean check shadowJar
# → build/libs/burp-mcp-server-<version>.jar
```
Stack: Kotlin 2.4.20 · JVM 21 · Gradle 8.12.1 · Montoya API 2026.7 · MCP Kotlin SDK 0.15.0 · Ktor 3.1.3.
Tests: `./gradlew check`.

## Status & roadmap

Current: **v0.2.0 (beta).** 133 unit tests; passed a multi-pass security & correctness code review and a round
of live-agent field testing. Planned: public 1.0, standalone stdio bridge, streamable-HTTP MCP federation.

## License

Released under the [MIT License](LICENSE). © 2026 RevoltSecurities.
