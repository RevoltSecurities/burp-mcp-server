#!/usr/bin/env python3
"""Zero-dependency version of sitemap_dump.py — speaks MCP Streamable-HTTP JSON-RPC over urllib.

    python examples/sitemap_dump_stdlib.py --url http://127.0.0.1:9876/mcp --host example.com
"""
import argparse
import json
import os
import urllib.request


class McpHttp:
    def __init__(self, url, token=""):
        self.url, self.token, self.sid, self.rid = url, token, None, 0

    def _post(self, body, notify=False):
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        if self.token:
            req.add_header("Authorization", "Bearer " + self.token)
        if self.sid:
            req.add_header("Mcp-Session-Id", self.sid)
        resp = urllib.request.urlopen(req, timeout=30)
        if resp.headers.get("Mcp-Session-Id"):
            self.sid = resp.headers.get("Mcp-Session-Id")
        if notify:
            resp.read(1)
            return None
        if "text/event-stream" in resp.headers.get("Content-Type", ""):
            for raw in resp:
                line = raw.decode("utf-8", "replace").strip()
                if line.startswith("data:"):
                    resp.close()
                    return json.loads(line[5:].strip())
        return json.loads(resp.read().decode())

    def rpc(self, method, params=None, notify=False):
        self.rid += 1
        body = {"jsonrpc": "2.0", "method": method}
        if not notify:
            body["id"] = self.rid
        if params is not None:
            body["params"] = params
        return self._post(body, notify)

    def initialize(self):
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "sitemap-dump", "version": "1.0"}})
        self.rpc("notifications/initialized", {}, notify=True)

    def call(self, name, args):
        res = self.rpc("tools/call", {"name": name, "arguments": args}).get("result", {})
        for block in res.get("content", []):
            txt = block.get("text", "")
            if txt.startswith(("{", "[")):
                return json.loads(txt)
        return res.get("structuredContent", {})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:9876/mcp")
    ap.add_argument("--host", required=True)
    ap.add_argument("--token", default=os.environ.get("REVOLT_MCP_TOKEN", ""))
    ap.add_argument("--in-scope-only", action="store_true")
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    c = McpHttp(args.url, args.token)
    c.initialize()
    cursor, total, page_no = None, 0, 0
    while True:
        page_no += 1
        a = {"host": args.host, "inScopeOnly": args.in_scope_only, "limit": args.limit}
        if cursor:
            a["cursor"] = cursor
        page = c.call("get_site_map", a)
        rows = page.get("items", [])
        print(f"[page {page_no}] {len(rows)} rows (total={page.get('totalCount')}, hasMore={page.get('hasMore')})")
        for row in rows:
            total += 1
            print(f"  {row.get('status','---')} {row.get('method','?'):6} {row['url']}  id={row['id']}")
            meta = c.call("get_http_message", {"id": row["id"], "part": "response", "section": "meta"})
            print(f"      response: {meta.get('mimeType')} {meta.get('totalBytes', 0)}B")
        cursor = page.get("nextCursor")
        if not cursor:
            break
    print(f"\nDone. {total} endpoint(s).")


if __name__ == "__main__":
    main()
