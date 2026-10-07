# Revolt MCP Server — Burp Suite extension

A dedicated, comprehensive **Model Context Protocol (MCP) server for Burp Suite**. It exposes Burp's
capabilities to AI agents and CLI clients over **selectable transports**, with **bearer-token auth + per-tool
gating**, a **modern in-Burp console**, and — the defining feature — **context-managed, paginated, structured
tool outputs** so large HTTP data never floods the model's context.

> Package `com.revoltsecurities.burpmcp` · Kotlin 2.4.20 / JVM 21 · Montoya API 2026.7 (runs on Burp 2025.4.4+).

## Highlights

- **~44 MCP tools** across read, action, analysis, scanner automation, race-conditions, federation and more.
- **Selectable transport:** Streamable-HTTP (default), HTTP+SSE, (stdio via bridge — planned). Pick it in the UI.
- **Auth & safety:** bearer token (constant-time), Origin/DNS-rebinding defense, an **unsafe master switch** and
  **per-tool toggles** enforced **on the MCP wire path itself** (not just a local path), optional **scope confinement**.
- **Context management:** keyset-cursor pagination, typed metadata rows (never raw bodies), `get_http_message`
  byte-range slicing with resumable markers, whole-envelope byte budget, binary omission.
- **Pentest automation:** drive Burp's crawler & scanner, Collaborator OOB verification, JS-endpoint recon,
  site-map injection, HTML/XML reports.
- **Race conditions:** `race_parallel_send` / `race_batch_send` (HTTP/2 single-packet best-effort) with grouped
  outcome analysis.
- **Integrations:** federate other MCP servers (`ext:<server>:<tool>`), ingest nuclei JSONL as Burp issues,
  SSRF-guarded Slack/Jira webhooks.

## Build

Requires **JDK 21** (the build targets JVM 21; Montoya is `compileOnly`). The Gradle wrapper pins Gradle 8.12.1.

```bash
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# → build/libs/burp-mcp-server-<version>.jar
./gradlew check   # run the test suite
```

## Install & run

1. Burp → **Extensions → Installed → Add → Java** → select the fat JAR.
2. Open the **Revolt MCP Server** tab → **Server** sub-tab: choose transport/host/port, optionally generate a
   bearer token (leave blank for loopback-only no-auth), tick **Allow mutating tools** if you want action tools,
   **Save settings**, **Start**.
3. **Connect** sub-tab gives ready-to-paste client config, e.g.:
   ```bash
   claude mcp add --transport http revolt-burp http://127.0.0.1:9876/mcp
   ```
4. **Tools** sub-tab toggles individual tools (restart the server to apply). **Dashboard** shows live status + metrics.

## Tool catalog (by domain)

- **Config/Status:** `status`, `burp_version`
- **Utilities:** `url_encode`/`url_decode`, `base64_encode`/`base64_decode`, `hash_compute`, `jwt_decode`, `decode_as`
- **Requests/Analysis:** `request_parse`, `response_parse`, `params_extract`, `find_reflected`, `diff_requests`
- **History / Site map / Scope:** `get_proxy_http_history`, `get_proxy_ws_history`, `get_site_map`, `scope_check`,
  `scope_include`*, `scope_exclude`*
- **Output:** `get_http_message` (byte-range slices)
- **Actions (mutating):** `http_send`, `repeater_create_tab`, `intruder_send`, `proxy_intercept`,
  `cookie_jar_get`, `cookie_set`, `issue_create`, `sitemap_add`
- **Scanner (Pro):** `scan_crawl_start`, `scan_audit_start`, `scan_task_status`, `scan_task_list`,
  `scan_task_delete`, `scan_report`; **Recon:** `extract_js_endpoints`
- **Collaborator (Pro):** `collaborator_generate`, `collaborator_poll`
- **Race:** `race_parallel_send`, `race_batch_send`
- **Integrations:** `ingest_nuclei_findings`, `webhook_notify`, federated `ext:<server>:<tool>`
- **Events:** `events_poll`

\* mutating tools require the unsafe master switch; scope-confined when enabled.

## Context-management model

List tools return a **page envelope** — typed rows + `nextCursor` (opaque keyset) + `hasMore`/`totalCount` +
a resumable `truncation` note — and **never embed request/response bodies**. Each row carries a stable `id`;
fetch bytes on demand with `get_http_message` (`section=meta|headers|body|full`, `offset`/`length`), which
slices large bodies and omits binary content. The whole envelope is capped to a byte budget (~25k tokens).

## Security model

- **Transport:** binds `127.0.0.1` by default; Origin/Host checked (DNS-rebinding defense).
- **Auth:** bearer token on HTTP transports (constant-time compare); blank token = loopback-only, unauthenticated.
- **Gating (wire path):** mutating tools need the unsafe master switch; Pro-only tools hidden in Community;
  per-tool enable toggles; optional scope confinement rejects out-of-scope sends/targets before any traffic.
- **Untrusted data:** federated/external results are trust-boundary wrapped; webhook URLs are SSRF-guarded.
- Secrets (bearer token) are encrypted at rest (AES-256-GCM); the master key sits beside the ciphertext in Burp
  Preferences (obfuscation vs. casual inspection, not a vault).

## Automation & agent playbooks

Any MCP SDK (Python, TypeScript, Go, …) or raw Streamable-HTTP client can connect — see runnable scripts in
[`examples/`](examples/README.md) (`sitemap_dump.py` lists a host's site map paginated and dumps each endpoint's
request/response in context-managed slices; a zero-dependency variant is included).

For the full capability map — what an agent can do framed like a human pentester (recon → analysis → manual
testing → automated scan → OOB verification → race conditions → reporting → integrations) — see
[`docs/AGENT_PLAYBOOKS.md`](docs/AGENT_PLAYBOOKS.md).

## Compatibility

Compiled against Montoya 2026.7; verified live on Burp **Professional 2025.4.4**. 2026.7-only APIs (the managed
`RequestExecutionEngine`) are reflection-detected and not required — race tools use `sendRequests` on all versions.

## License

TBD.
