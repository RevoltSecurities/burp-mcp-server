# Burp Suite Montoya API — Maintainer Reference & Version-Split Guide

> **Purpose.** A standing reference for this extension so the Montoya surface never has to be
> re-researched from scratch. It records the API shape we compile against (**montoya-api 2026.7**), the
> parts that are **version-split** against our runtime floor (**Burp 2025.4.4**), and the correctness
> pitfalls that have actually bitten extension authors.
>
> **How to read the confidence tags.** Every signature is tagged:
> - **[javadoc]** — read directly from the 2026.7 javadoc (`portswigger.github.io/burp-extensions-montoya-api/javadoc/`).
> - **[verified-live]** — additionally confirmed against our live Burp (Professional 2026.7.3).
> - **[knowledge]** — from practitioner knowledge / examples; ~90% confidence. **Verify on the live
>   javadoc before writing new code that hinges on the exact signature.**
>
> Primary sources are listed at the bottom. When in doubt, the javadoc index is authoritative.

---

## 0. The version-split answer (read this first)

Our `CLAUDE.md` invariant: *code compiles against Montoya 2026.7 but must run on Burp 2025.4.4; any
2026.7-only API must be reflection-guarded and degrade.* Here is the concrete hazard list.

| API | Reached via | Introduced | Safe on 2025.4.4? | In our code |
|---|---|---|---|---|
| `organizer().items()` / `items(OrganizerItemFilter)` → `List<OrganizerItem>` | `Organizer` | **2025.7 / 2025.7.2** | **NO** → `NoSuchMethodError` | reflection-guarded in `MontoyaActions.organizerItems()` ✔ |
| `organizer().sendToOrganizer(...)` | `Organizer` | 2023.10.1.1 | **YES** (old) | straight-line, fine ✔ |
| `http().createRequestEngine()` / `createRequestEngine(RequestEngineOptions)` → `RequestExecutionEngine` | **`Http`** (not a top-level sub-API) | not pinned to a release note; treat as > 2025.4.4 | **treat as NO** | reflection-detected via `managedEngineAvailable()` ✔ |
| `ai()` (Burp AI sub-API) | `MontoyaApi` | ~2025.x | **NO** | not referenced — keep it that way |
| `bambda()` | `MontoyaApi` | recent (2025.x) | **verify floor** | used by `bambda_import`; confirm it exists on 2025.4.4 or guard it |
| `userInterface().registerSettingsPanel(...)` | `UserInterface` | **2025.5** | **NO** | not referenced |
| 2025.8 additions: open Settings dialog, editor caret position, HTTP/2 raw header bytes | various | **2025.8** | **NO** | not referenced |

**Key correction to a common misconception:** `RequestExecutionEngine` is reached via
`montoyaApi.http().createRequestEngine()`. There is **no** top-level `montoyaApi.requestExecutionEngine()`.
So the straight-line risk is any call to `http().createRequestEngine(...)` or `organizer().items(...)`.

**Guard pattern we use (and should keep):** resolve the method via reflection once, cache a boolean,
degrade. Never reference the version-split symbol (`RequestExecutionEngine`, `OrganizerItem`, …) on a
compiled straight-line path — the JVM links call sites lazily, so the guarded `organizer.items()` call and
its `OrganizerItem`-typed lambda only link *after* the early-return guard passes. That is why
`MontoyaActions.organizerItems()` is safe. (Live-confirmed: `organizer_items` works on 2026.7.3.)

**Bug-hunt lead:** audit every compiled reference to `createRequestEngine`, `organizer().items(`, `ai()`,
`bambda()`, `registerSettingsPanel`. Each is a candidate `NoSuchMethodError` on 2025.4.4.

---

## 1. `MontoyaApi` entry object — the 21 sub-APIs [javadoc]

```
Ai            ai()            // Professional only; version-split (recent)
Bambda        bambda()        // version-split (recent) — verify 2025.4.4 floor
BurpSuite     burpSuite()
Collaborator  collaborator()  // Professional only
Comparer      comparer()
Decoder       decoder()
Extension     extension()
Http          http()
Intruder      intruder()
Logging       logging()
Organizer     organizer()
Persistence   persistence()
Project       project()
Proxy         proxy()
Repeater      repeater()
Scanner       scanner()       // Professional only
Scope         scope()
SiteMap       siteMap()
UserInterface userInterface()
Utilities     utilities()
WebSockets    websockets()    // all-lowercase 's' — NOT webSockets()
```

Gotchas that matter here:
- **`websockets()` is all-lowercase.** Easy to mistype as `webSockets()`.
- `scanner()`, `collaborator()`, `ai()` are **Professional-only** → throw under Community. Our
  `ToolRegistry` pro-gates these at registration, which is correct.
- Sub-API return types for the ones we touch (member lists in later sections):
  - `repeater()` → `Repeater`: `sendToRepeater(HttpRequest)`, `sendToRepeater(HttpRequest, String caption)`
    — **populates a tab only; does not send.** [knowledge]
  - `burpSuite()` → `BurpSuite`: `version()`, `exportProjectOptionsAsJson(...)`,
    `importProjectOptionsFromJson(...)`, `exportUserOptionsAsJson(...)`, `importUserOptionsFromJson(...)`,
    `shutdown()`. [knowledge] `version()` → `Version` (`name/major/minor/build/edition`); `edition()` →
    `BurpSuiteEdition` enum (`COMMUNITY_EDITION`, `PROFESSIONAL`, `ENTERPRISE_EDITION`). Our `BurpEnv`
    edition detection depends on this.
  - `utilities()` → `Utilities`: `base64Utils, urlUtils, byteUtils, randomUtils, stringUtils, cryptoUtils,
    htmlUtils, compressionUtils, numberUtils`. [knowledge]
  - `logging()` → `Logging`: `logToOutput`, `logToError`, `raiseInfo/Debug/Error/CriticalEvent`. [knowledge]
  - `extension()` → `Extension`: `setName`, `registerUnloadingHandler`, `filename`, `isBapp`. [knowledge]
  - `userInterface()` → `UserInterface`: `registerSuiteTab`, `registerContextMenuItemsProvider`,
    `menuBar()`, `createHttpRequestEditor/ResponseEditor`, `applyThemeToComponent`,
    `currentDisplayTheme()`, `swingUtils()`, and `registerSettingsPanel(...)` (**2025.5+**). [knowledge]

---

## 2. HTTP

### `Http` interface [javadoc]
```
Registration                  registerHttpHandler(HttpHandler handler)
Registration                  registerSessionHandlingAction(SessionHandlingAction action)
HttpRequestResponse           sendRequest(HttpRequest request)
HttpRequestResponse           sendRequest(HttpRequest request, HttpMode httpMode)
HttpRequestResponse           sendRequest(HttpRequest request, HttpMode httpMode, String connectionId)
HttpRequestResponse           sendRequest(HttpRequest request, RequestOptions requestOptions)
List<HttpRequestResponse>     sendRequests(List<HttpRequest> requests)
List<HttpRequestResponse>     sendRequests(List<HttpRequest> requests, HttpMode httpMode)
RequestExecutionEngine        createRequestEngine()                               // version-split
RequestExecutionEngine        createRequestEngine(RequestEngineOptions options)   // version-split
ResponseKeywordsAnalyzer      createResponseKeywordsAnalyzer(List<String> keywords)
ResponseVariationsAnalyzer    createResponseVariationsAnalyzer()
CookieJar                     cookieJar()
```

### `RequestOptions` [javadoc]
```
static RequestOptions requestOptions()
RequestOptions withHttpMode(HttpMode httpMode)
RequestOptions withConnectionId(String connectionId)
RequestOptions withUpstreamTLSVerification()
RequestOptions withRedirectionMode(RedirectionMode redirectionMode)
RequestOptions withServerNameIndicator(String serverNameIndicator)
RequestOptions withResponseTimeout(long timeoutMs)   // MILLISECONDS
```
`HttpMode` enum: `AUTO`, `HTTP_1`, `HTTP_2`. [knowledge]

### `HttpRequest` — factories [javadoc]
```
static HttpRequest httpRequest()
static HttpRequest httpRequest(ByteArray request)
static HttpRequest httpRequest(String request)
static HttpRequest httpRequest(HttpService service, ByteArray request)
static HttpRequest httpRequest(HttpService service, String request)
static HttpRequest httpRequestFromUrl(String url)
static HttpRequest http2Request(HttpService service, List<HttpHeader> headers, ByteArray body)
static HttpRequest http2Request(HttpService service, List<HttpHeader> headers, String body)
```

### `HttpRequest` — withers (immutable; each returns a NEW request) [javadoc]
```
withService(HttpService) · withPath(String) · withMethod(String)
withHeader(HttpHeader) · withHeader(String,String)
withAddedHeader(String,String|HttpHeader) · withAddedHeaders(...)
withUpdatedHeader(String,String|HttpHeader) · withUpdatedHeaders(...)
withRemovedHeader(String|HttpHeader) · withRemovedHeaders(...)
withParameter(HttpParameter)                      // UPSERT semantics
withAddedParameters(...) · withUpdatedParameters(...) · withRemovedParameters(...)
withBody(String) · withBody(ByteArray)
withMarkers(List<Marker>|Marker...)
withTransformationApplied(HttpTransformation)
withDefaultHeaders() · copyToTempFile()
```
Accessors: `isInScope()`, `httpService()`, `url()`, `method()`, `path()`, `query()`,
`pathWithoutQuery()`, `fileExtension()`, `contentType()`, `parameters()`/`parameters(type)` →
`List<ParsedHttpParameter>`, `parameter(name[,type])`, `parameterValue(...)`, `hasParameter(...)`,
`header(name)`, `headerValue(name)`, `headers()`, `httpVersion()`, `bodyOffset()`, `body()` → `ByteArray`,
`bodyToString()`, `markers()`, `contains(String, boolean)`/`contains(Pattern)`, `toByteArray()`.

### `HttpResponse` [knowledge]
Factories `httpResponse()` / `httpResponse(ByteArray)` / `httpResponse(String)`. Accessors:
`statusCode()` (short), `reasonPhrase()`, `httpVersion()`, `headers()`, `header(name)`, `body()`,
`bodyToString()`, `bodyOffset()`, `cookies()`, `mimeType()`/`statedMimeType()`/`inferredMimeType()`,
`contains(...)`, `keywords(...)`, `attributes(...)`. Withers mirror the request.

### `HttpService` [knowledge]
```
static HttpService httpService(String baseUrl)
static HttpService httpService(String host, boolean secure)
static HttpService httpService(String host, int port, boolean secure)
```
Accessors: `host()`, `port()`, `secure()`, `ipAddress()`.

### `HttpRequestResponse` [knowledge]
`request()`, `response()`, `annotations()` (→ `Annotations`: `notes()`, `highlightColor()`),
`timingData()`, `url()`, `httpService()`; withers `withAnnotations(...)`, `copyToTempFile()`; factory
`httpRequestResponse(req, resp)`.

### `HttpParameter` / `ParsedHttpParameter` [knowledge]
Build with `HttpParameter.urlParameter(name,value)`, `bodyParameter(...)`, `cookieParameter(...)`, or
`parameter(name,value,HttpParameterType)`. `HttpParameterType`: `URL, BODY, COOKIE, XML, XML_ATTRIBUTE,
MULTIPART_ATTRIBUTE, JSON`. `ParsedHttpParameter` adds `name/value/type/nameOffsets/valueOffsets`.

### HTTP pitfalls (the real trip-ups)
1. **Build-from-string without a service throws on send.** `httpRequest(String)` /
   `httpRequest(ByteArray)` carries no `HttpService`. You **must** `withService(...)` (or use
   `httpRequestFromUrl(url)` / `httpRequest(service, bytes)`) before `sendRequest`. The #1 extension bug.
2. **Immutability is total.** Every `with*` returns a new object; a discarded result is a no-op. Capture
   the return value.
3. **Content-Length is managed for you.** The builders/senders keep `Content-Length` consistent with the
   body. Convenient, but it frustrates deliberate desync/smuggling payloads — construct raw `ByteArray`
   and know Burp may still normalize on send. (This is why our `SessionInjector` / race tools take care to
   preserve crafted raw requests and avoid re-normalizing.) [knowledge on exact mechanics]
4. **`withParameter` is upsert; `withAddedParameters` always adds** (can duplicate). Choose deliberately.
5. **`withUpdatedHeader` replaces; `withAddedHeader` can duplicate** (e.g. two `Cookie:`), which some
   targets reject.
6. **`sendRequest` blocks** the calling thread until response/timeout — never on the EDT (§9).
7. **`withPath(String)`** expects a leading `/` and doesn't touch the query unless you include it.
8. **`sendRequests` (plural) is sequential/batched, not high-throughput** — that's `createRequestEngine`
   (version-split).

---

## 3. Scanner  *(Professional only)*

### `Scanner` interface [javadoc]
```
Registration registerActiveScanCheck(ActiveScanCheck check, ScanCheckType type)
Registration registerPassiveScanCheck(PassiveScanCheck check, ScanCheckType type)
Registration registerAuditIssueHandler(AuditIssueHandler handler)
Registration registerScanCheck(ScanCheck scanCheck)                 // DEPRECATED
Registration registerInsertionPointProvider(AuditInsertionPointProvider provider)
Crawl        startCrawl(CrawlConfiguration configuration)
Audit        startAudit(AuditConfiguration configuration)
void         generateReport(List<AuditIssue> issues, ReportFormat format, Path path)
BChecks      bChecks()
```

Deltas worth knowing:
- **No `startCrawlAndAudit(...)` and no `CrawlAndAudit` type** in 2026.7. Crawl and audit are two
  operations (`startCrawl` then `startAudit`). If any code references `startCrawlAndAudit`, it's a bug.
- **`registerScanCheck(ScanCheck)` is deprecated** → prefer the `registerActiveScanCheck` /
  `registerPassiveScanCheck` pair (2023.x split).
- **No `ConsolidationAction` enum in Montoya.** The legacy `consolidateDuplicateIssues` (-1/0/1) concept
  is gone; `AuditIssueHandler` only *notifies*, it does not vote on consolidation. Our `createIssue`
  dedups by `name()+baseUrl()` itself, which is the right approach.

### Scan tasks [javadoc for types; members knowledge]
`startAudit` → `Audit`, `startCrawl` → `Crawl` (both extend a scan-task base:
`statusMessage()`, `requestCount()`, `errorCount()`, `delete()`). `Audit` adds `addRequest(HttpRequest)`,
`addRequest(HttpRequest, List<AuditInsertionPoint>)`, `addRequestResponse(HttpRequestResponse)`,
`insertionPointCount()`, `issues()` → `List<AuditIssue>`. `Crawl` adds seed-URL handling. **Verify these
member names on the live javadoc before new code.**

### Configurations [knowledge — the config page 404'd during research; verify]
```
AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration)
BuiltInAuditConfiguration: LEGACY_ACTIVE_AUDIT_CHECKS, LEGACY_PASSIVE_AUDIT_CHECKS
CrawlConfiguration.crawlConfiguration(String... seedUrls)
```
Newer versions can load a saved named Burp config — verify the exact factory before compiling.

### `AuditIssueHandler` [javadoc]
```
void handleNewAuditIssue(AuditIssue auditIssue)
```

### Registering your own issue [knowledge]
```
AuditIssue.auditIssue(String name, String detail, String remediation, String baseUrl,
    AuditIssueSeverity severity, AuditIssueConfidence confidence, String background,
    String remediationBackground, AuditIssueSeverity typicalSeverity,
    HttpRequestResponse... requestResponses)
```
`severity` appears at position 5 and the *typical* severity at position 9. `siteMap().add(AuditIssue)`
records an issue to the site map. Note there is **no stable string "definition id"** — the stable handle
is `AuditIssueDefinition.typeIndex()` (an int). Using the display `name()` as a definition id is a wart,
not a stable identifier.

---

## 4. Scope [javadoc]
```
boolean      isInScope(String url)
void         includeInScope(String url)
void         excludeFromScope(String url)
Registration registerScopeChangeHandler(ScopeChangeHandler handler)
```
Gotchas:
- **String URL, not `java.net.URL`** (the deliberate break from the legacy API). Pass a full absolute URL
  (`https://example.com/`). A bare host or relative path will not match as expected.
- `isInScope` honors Burp's current scope mode (simple vs advanced). In advanced mode `includeInScope(url)`
  adds a rule for that literal URL/prefix.
- `includeInScope`/`excludeFromScope` **mutate the user's project scope** (a config side effect). Read-only
  confinement should use `isInScope` only — which is exactly what `ScopeGuard` does.
- Trailing slash / path sensitivity: `https://example.com` vs `…/` can match differently. Normalize first.

---

## 5. Collaborator  *(Professional only)*

### `Collaborator` [javadoc]
```
CollaboratorClient           createClient()
CollaboratorClient           restoreClient(SecretKey secretKey)
CollaboratorPayloadGenerator defaultPayloadGenerator()
```
### `CollaboratorClient` [javadoc]
```
CollaboratorPayload generatePayload(PayloadOption... options)
CollaboratorPayload generatePayload(String customData, PayloadOption... options)
List<Interaction>   getAllInteractions()
List<Interaction>   getInteractions(InteractionFilter filter)
CollaboratorServer  server()
SecretKey           getSecretKey()
```
Model & persistence:
- **Pull model:** hold a client, generate payloads, embed them, poll `getAllInteractions()` on your own
  schedule. Burp does not push.
- **Persist `getSecretKey()` and rebuild with `restoreClient(secretKey)`** to survive reloads.
  `SecretKey.secretKey(String)` reconstructs from string form [knowledge]. **A fresh `createClient()` after
  reload is a different identity and will not see earlier interactions — restore, don't recreate.** Our
  `CollaboratorKeyStore` persists keys for exactly this reason.
- `PayloadOption.WITHOUT_SERVER_LOCATION` yields an id-only payload. [knowledge]
- `Interaction`: `id/type/clientIp/timeStamp/dnsDetails/httpDetails/smtpDetails`. [knowledge]

---

## 6. Intruder / payloads — **the API does NOT launch attacks**

### `Intruder` interface [javadoc]
```
Registration registerPayloadProcessor(PayloadProcessor processor)
Registration registerPayloadGeneratorProvider(PayloadGeneratorProvider provider)
void         sendToIntruder(HttpService service, HttpRequestTemplate template)
void         sendToIntruder(HttpService service, HttpRequestTemplate template, String tabCaption)
void         sendToIntruder(HttpRequest request)
void         sendToIntruder(HttpRequest request, String tabCaption)
```

**Confirmed: Montoya exposes no method to start, run, or read the results of an Intruder attack.** It only
(a) **populates an Intruder tab** for the human to run, and (b) lets you register payload
generators/processors that Burp calls *during* a user-driven attack. There is no `startAttack`, no
`AttackResults`.

**Consequence for us:** `intruder_attack` must implement the attack loop itself with
`http().sendRequest(...)` (or `createRequestEngine` where available) over computed payload positions — the
API will not do it. This is exactly why `PayloadEngine` + `sendRequests` exist in this codebase. The
`§...§` marker handling is ours, not Burp's.

---

## 7. Organizer & RequestExecutionEngine (see §0)

### `Organizer` [javadoc]
```
void                 sendToOrganizer(HttpRequest request)                 // 2023.10.1.1 — safe
void                 sendToOrganizer(HttpRequestResponse requestResponse) // safe
List<OrganizerItem>  items()                                             // 2025.7+ — version-split
List<OrganizerItem>  items(OrganizerItemFilter filter)                   // 2025.7+ — version-split
```
Keep **both** `items(...)` overloads behind the same reflection guard. `OrganizerItem` [knowledge]:
`annotations()`, `httpRequestResponse()`, plus item metadata (`id()`, `status()` — the two we currently
surface; there is room to expose URL/notes as an enhancement).

### `RequestExecutionEngine`
Reached via `http().createRequestEngine()` / `createRequestEngine(RequestEngineOptions)`. High-throughput
sending engine. Introduction release not pinned → **keep reflection-guarded**.

---

## 8. Persistence

### `Persistence` [javadoc]
```
PersistedObject extensionData()   // stored in the Burp PROJECT file (per-project; lost in temp projects)
Preferences     preferences()     // Java Preferences store; global to the install, survives reload
```
### `PersistedObject` / `Preferences` typed accessors [knowledge — verify before new code]
```
String  getString(key)  / setString(key,v)         Integer getInteger(key) / setInteger(key,v)
Long    getLong(key)    / setLong(key,v)           Boolean getBoolean(key) / setBoolean(key,v)
Short   getShort(...)   / Byte getByte(...)         ByteArray getByteArray(key) / setByteArray(key,v)
PersistedObject getChildObject(key) / setChildObject(key,v)
HttpRequest getHttpRequest(key) / HttpRequestResponse getHttpRequestResponse(key)  // extensionData only
Set<String> stringKeys() / booleanKeys() / ...      void deleteString(key) / delete...(key)
```
Semantics that bite:
- **`extensionData()` = project file** (different per project, lost in a temporary project).
  **`preferences()` = global Java store** (cross-project, survives reload). Our `McpSettings` correctly
  uses preferences (JSON + `SecretCipher`) for cross-project secrets.
- Getters return **boxed nullables** (`Integer`/`Boolean`): a missing key is `null`, not 0/false.
  Null-check.
- No transactions; last write wins. Safe off-thread; never bulk-persist on the EDT.

---

## 9. Threading / EDT rules [knowledge — PortSwigger guidance + practitioner consensus]

- **Never call blocking/HTTP/Montoya data calls on the Swing EDT.** `sendRequest(s)`, scanner start,
  collaborator poll, site-map/proxy-history reads, bulk persistence all block and freeze Burp's UI on the
  EDT. Our `CLAUDE.md` rule matches this.
- **Handler callbacks run on Burp worker threads, NOT the EDT, and may run concurrently.**
  `HttpHandler.handleHttpRequestToBeSent/handleHttpResponseReceived`, the `ProxyRequestHandler` /
  `ProxyResponseHandler` methods, `SessionHandlingAction.performAction`, and
  `AuditIssueHandler.handleNewAuditIssue` are all off-EDT and possibly multi-threaded. Handler state must
  be thread-safe; hop to the EDT with `SwingUtilities.invokeLater` to touch Swing.
- **Proxy handlers must return quickly** and return an action object
  (`ProxyRequestReceivedAction.continueWith(...)/.drop()/.intercept()`). Blocking stalls that connection.
- **In this codebase:** MCP tool dispatch runs on **Netty worker threads** (off-EDT), so `api.http()` calls
  inside tool handlers are legal. The UI (`MainTab`) marshals blocking work to named daemon threads and
  results back via `invokeLater`. `MontoyaSessionHandling` offloads token refresh to a daemon thread with
  an `AtomicBoolean` single-flight so it never blocks Burp's HTTP pipeline. Keep these patterns.
- `registerHttpHandler` sees **all** Burp tool-originated traffic (Repeater/Scanner/…), so filter by tool
  source if you only care about proxy.

---

## 10. Session handling

### `SessionHandlingAction` [javadoc]
```
String       name()
ActionResult performAction(SessionHandlingActionData actionData)
```
### `ActionResult` [javadoc]
```
static ActionResult actionResult(HttpRequest request)
static ActionResult actionResult(HttpRequest request, Annotations annotations)
HttpRequest request()
Annotations annotations()
```
### `SessionHandlingActionData` [knowledge]
`request()` (the base request to modify), `annotations()`, `macroRequestResponses()` →
`List<HttpRequestResponse>` (output of any macro that ran immediately before this action), plus tool
source. Typical pattern: read a fresh token out of `macroRequestResponses()`, mutate the base request,
return `actionResult(modified)`. Runs off-EDT and may be called concurrently → keep stateless/synchronized.

### Cookie jar [knowledge]
`http().cookieJar()` → `CookieJar`: `cookies()` → `List<Cookie>`, `setCookie(name,value,path,domain,
Instant expiration)`, `setCookie(name,value,path,domain)`, plus URL overloads. `Cookie`:
`name/value/domain/path/expiration()`. The jar is Burp-wide; writes affect all tools.

---

## 11. WebSockets

### `WebSockets` [javadoc]
```
Registration               registerWebSocketCreatedHandler(WebSocketCreatedHandler handler)
ExtensionWebSocketCreation createWebSocket(HttpService service, String path)
ExtensionWebSocketCreation createWebSocket(HttpRequest upgradeRequest)
```
Method is `registerWebSocketCreated**Handler**` (past tense). `ExtensionWebSocketCreation` [knowledge]:
`hasErrors()`, `webSocket()`.

### Proxy WebSocket surface [javadoc]
```
List<ProxyWebSocketMessage> webSocketHistory()
List<ProxyWebSocketMessage> webSocketHistory(ProxyWebSocketHistoryFilter filter)
Registration registerWebSocketCreationHandler(ProxyWebSocketCreationHandler handler)
```
### Sending messages [knowledge — verify member signatures]
```
WebSocket:      sendTextMessage(String), sendBinaryMessage(ByteArray)
ProxyWebSocket: sendTextMessage(String, Direction), sendBinaryMessage(ByteArray, Direction)
Direction: CLIENT_TO_SERVER, SERVER_TO_CLIENT
```

---

## 12. Deprecations & breaking changes to track (2024.x → 2026.x)

High confidence (javadoc/release notes):
- **`Scanner.registerScanCheck(ScanCheck)` deprecated** → use the active/passive pair.
- **`organizer().items()` / `OrganizerItem` added 2025.7/2025.7.2** → hard `NoSuchMethodError` on 2025.4.4
  (our primary hazard, date-confirmed).
- **2025.8:** programmatic open-Settings dialog, message-editor caret positioning, HTTP/2 raw header bytes.
- **2025.5:** `UserInterface.registerSettingsPanel(...)` / `SettingsPanel`.
- **`ai()` and `bambda()`** are recent top-level additions → version-split risks against a 2025.4.4 floor.

Legacy → Montoya migration map (if any old `burp.*` code ever appears): `byte[]` → `ByteArray`;
`java.net.URL` scope → `String url`; mutable request/response → **immutable** `HttpRequest`/`HttpResponse`
withers; `makeHttpRequest` → `http().sendRequest`; `IScannerCheck.consolidateDuplicateIssues` → **gone**.

---

## Items to verify on the live javadoc before new code hinges on them
These were answered from practitioner knowledge during research (detail page 404'd or not fetched):
- `AuditConfiguration`/`CrawlConfiguration` factory names and `BuiltInAuditConfiguration` constants.
- `Audit`/`Crawl` member methods (`addRequest`, `addSeedUrl`, `issues()`, `statusMessage()`).
- `PersistedObject`/`Preferences` full typed-accessor list.
- `WebSocket`/`ProxyWebSocket` send/handler signatures and the `Direction` enum.
- `Repeater.sendToRepeater` overloads; `Version.edition()` → `BurpSuiteEdition` constants.

## Primary sources
- Javadoc root: <https://portswigger.github.io/burp-extensions-montoya-api/javadoc/>
- `organizer().items()` / `OrganizerItem` introduced: <https://portswigger.net/burp/releases/professional-community-2025-7> (+ 2025.7.2)
- 2025.8 Montoya additions: <https://portswigger.net/burp/releases/professional-community-2025-8>
- `sendToOrganizer` since 2023.10.1.1: <https://portswigger.net/burp/releases/professional-community-2023-10-1-1>
- Examples repo: <https://github.com/PortSwigger/burp-extensions-montoya-api-examples>
- Extension creation docs: <https://portswigger.net/burp/documentation/desktop/extensions/creating>

---
*Compiled from a dedicated Montoya research pass + live verification against Burp Professional 2026.7.3.
Update the version-split table (§0) whenever we bump the compile target or raise/lower the 2025.4.4
runtime floor.*
