# Examples — automating Revolt MCP Server

Scripts that connect to the running extension and drive it like any MCP client.

Start the server first (Burp → **Revolt MCP Server** → Server → Start). Note the endpoint (default
`http://127.0.0.1:9876/mcp`) and bearer token (if set).

## `sitemap_dump.py` — official MCP Python SDK

Lists a host's site map (paginated) and dumps each endpoint's request/response in context-managed,
byte-ranged slices.

```bash
pip install mcp
python examples/sitemap_dump.py --url http://127.0.0.1:9876/mcp --host example.com --out out/
# with auth:  --token "$TOKEN"
```

## `sitemap_dump_stdlib.py` — zero dependencies

Same thing using only the Python standard library (raw Streamable-HTTP JSON-RPC) — handy when you can't
`pip install`.

```bash
python examples/sitemap_dump_stdlib.py --url http://127.0.0.1:9876/mcp --host example.com
```

## `intruder_attack.py` — programmatic Intruder (zero dependencies)

Runs the `intruder_attack` tool (sniper / pitchfork / clusterbomb) and prints grouped outcomes + a
per-payload sample, then fetches a representative response. `intruder_attack` is **mutating**, so enable
**"Allow mutating tools"** on the Server tab first, and keep the host in scope if confinement is on.
**Only run against targets you're authorized to test.**

```bash
# sniper (default): fuzz one §…§ position with a payload list
python examples/intruder_attack.py --host example.com --payloads "admin,root,test,backup"

# clusterbomb with an explicit template + multiple payload sets ( ';' separates sets, ',' separates items )
python examples/intruder_attack.py --host example.com --attack clusterbomb \
  --template $'POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=§admin§&pw=§x§' \
  --payload-sets "admin,root ; a,b,c"
```

Both work against any MCP server; swap the URL/token for yours. For the SSE transport, point your client at
`/sse` after switching the Server tab's transport to SSE.

> After building a new JAR you must **reload it in Burp** for new tools (e.g. `intruder_attack`) to appear —
> a client connected to an older running build will report "tool not found".
