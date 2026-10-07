# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Burp Suite extension (Kotlin + Montoya API) that runs an **MCP server**, exposing Burp to AI agents and
scripts. The design priority is **context-managed output** (paginated, typed, byte-budgeted) and **safety
gating** on the MCP wire path. See `README.md` for the user-facing surface and `docs/AGENT_PLAYBOOKS.md` for
the tool workflows.

## Build / test commands

**JDK 21 is required and must be set explicitly** — the system default is Java 24, which Gradle 8.12.1 will not
run on, and the build targets JVM 21. Prefix every Gradle command:

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64   # any JDK 21

./gradlew clean shadowJar        # fat JAR → build/libs/burp-mcp-server-<version>.jar (load this in Burp)
./gradlew check                  # compile + run all tests
./gradlew clean check shadowJar  # full gate (what CI runs)

# single test class / method
./gradlew test --tests 'com.revoltsecurities.burpmcp.tools.PayloadEngineTest'
./gradlew test --tests 'com.revoltsecurities.burpmcp.tools.PayloadEngineTest.sniper fuzzes one position at a time keeping base values'
```

There is no detekt/ktlint wired. The Montoya API is `compileOnly` (Burp provides it at runtime).

### Running / smoke-testing the live server

The server runs *inside Burp* (load the JAR, Server tab → Start). It cannot be launched standalone. To exercise
it end-to-end, start it in Burp on `127.0.0.1:9876`, then drive it over MCP. Zero-dependency clients live in
`examples/` (and ad-hoc scripts belong in the session scratchpad, not the repo). `intruder_attack` and other
mutating tools require the **Allow mutating tools** switch to be on.

## Architecture (the big picture)

Entry point `extension/BurpMcpExtension.kt` → `extension/App.kt` wires every subsystem and the suite-tab UI,
and registers an unloading handler. Packages under `src/main/kotlin/com/revoltsecurities/burpmcp/`:

- **`mcp/`** — server lifecycle + transport. `McpServerSupervisor` owns start/stop/restart (off the EDT) and a
  shared SDK `Server`. `McpServerFactory.buildSpecs()` is the **single source of truth**: it builds the full
  `ToolSpec` list once; `build()` registers it and `toolMetadata()` feeds the UI from the *same* list (no
  parallel tables). `McpModule.installMcpModule()` is the one place the Ktor wiring lives (auth/Origin/Host gate
  ahead of routing, health route, transport selection). `ToolRegistry` enforces, **on the wire path**, per-tool
  enable toggles + Professional gating (at registration) and the unsafe-master-switch for mutating tools (at
  dispatch). `AuthGate` is the constant-time bearer check.

- **Tool pattern (`tools/`)** — every tool is a `ToolSpec{id, description, inputSchema, mutating, proOnly,
  handler}`. Handlers take `Args` (JSON arg accessor) and return a `CallToolResult` via `Results` (which only
  emits `structuredContent` for object-shaped values). Schemas are built with `SchemaBuilder`; shared parameter
  wording lives in `Descriptions` (keep it there to prevent model mis-calls). Tool *logic* is pure and depends
  on **seam interfaces** — `BurpDataSource`, `BurpActions`, `BurpScanner`, `BurpCollaborator` — whose Montoya
  implementations (`Montoya*.kt`) are isolated and compiled-only. This is why most logic is unit-testable with
  fakes. `ScopeGuard` is the shared scope-confinement check; use it (not ad-hoc checks) for new send/target
  tools, and check scope **before** building any Montoya object.

- **`output/`** — the context-management layer (the project's whole point). `Pager` does **keyset-cursor**
  pagination: it resumes with `key > lastCursorKey`, so **every list's sort key MUST be unique** (e.g. site-map
  rows include an index because many entries share a URL — don't regress this). `CursorCodec` encodes opaque
  base64 cursors bound to a filter hash. `ByteBudget` trims a page to a whole-response byte budget (never
  mid-row). `BodySlicer` returns resumable byte-range slices snapped to UTF-8 boundaries and omits binary.
  `MessageRegistry` maps stable row `id`s → lazy byte handles so lists carry ids, not bodies, and
  `get_http_message` fetches on demand.

- **`integrations/`** — MCP federation (`SdkExternalClients`, `Federation` namespacing + trust-wrap), nuclei
  ingestion (`NucleiIngest`), webhooks (`Webhooks`, SSRF-guarded by resolving the host).

- **`events/`** — `EventBuffer` (ring buffer) + `MontoyaEventSource` (passthrough HTTP + audit-issue handlers)
  feed the `events_poll` tool.

- **`config/`** — `McpSettings` (persisted to Burp preferences as JSON; secrets encrypted via `SecretCipher`),
  `SettingsStore`, `BurpEnv` (edition detection).

- **`ui/`** — theme-reactive Swing (`ui/design/DesignTokens` reads `UIManager` at paint time; no L&F override),
  custom components, tabbed `MainTab`. **Never block the EDT and never call `api.http()`/Montoya from the EDT**;
  blocking work is dispatched to daemon threads.

## Repo-specific invariants (do not regress)

- **Montoya version split:** code compiles against Montoya 2026.7 but must run on Burp **2025.4.4**. Any
  2026.7-only API (currently `RequestExecutionEngine`, `Organizer.items()`) must be **reflection-guarded** and
  degrade — never referenced on a straight-line compiled path, or it NoSuchMethods at runtime.
- **Gating is wire-path:** mutating/pro/scope/enable checks run for *every* tool including federated `ext:*` —
  enforce new mutating tools via `ToolSpec.mutating = true` + `ScopeGuard`, not bespoke logic.
- **Context management:** list tools return typed rows (never bodies) + a keyset cursor; large bodies go through
  `get_http_message`/`BodySlicer`; keep sort keys unique.
- **File-path tools are sandboxed:** `ReportPath` and `Wordlists` resolve filename-only under a base dir and
  reject traversal — keep that for any new file access.

## Git / release conventions

- **Commits are authored solely by `th3sanjai <revoltsec.github@gmail.com>` — do NOT add any Claude /
  Co-Authored-By attribution** to commits or PRs in this repo.
- **`docs/research/` is private** (gitignored, local-only); never commit it. `docs/AGENT_PLAYBOOKS.md`,
  `docs/assets/`, and `examples/` are public.
- Pushing a `v*` tag triggers `.github/workflows/release.yml` (build + test + publish a GitHub Release with the
  JAR). `.github/workflows/ci.yml` builds/tests on push/PR to `main`.
