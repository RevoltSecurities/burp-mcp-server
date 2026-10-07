#!/usr/bin/env python3
"""List a host's Burp site map (paginated) and dump each endpoint's request/response via the official
MCP Python SDK over Streamable-HTTP.

    pip install mcp
    python examples/sitemap_dump.py --url http://127.0.0.1:9876/mcp --host example.com --out out/

Demonstrates the context-managed flow: get_site_map returns typed rows (no bodies) + a keyset cursor;
get_http_message fetches each row's bytes in bounded, resumable slices.
"""
import argparse
import asyncio
import json
import os

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


def structured(result):
    """Prefer structuredContent; fall back to the mirrored JSON text block."""
    sc = getattr(result, "structuredContent", None)
    if sc:
        return sc
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"text": text}
    return {}


async def fetch_body(session, msg_id, part, max_bytes):
    """Pull a message part in slices until the whole body (up to max_bytes) is retrieved."""
    chunks, offset = [], 0
    while True:
        res = structured(await session.call_tool(
            "get_http_message",
            {"id": msg_id, "part": part, "section": "body", "offset": offset, "length": 8192},
        ))
        if res.get("bodyEncoding") == "omitted":
            return f"<{res.get('mimeType')} binary, {res.get('totalBytes', 0)} bytes omitted>"
        chunks.append(res.get("content", ""))
        trunc = res.get("truncation")
        offset = (res.get("bodyOffset", 0) + res.get("bodyLength", 0))
        if not trunc or sum(len(c) for c in chunks) >= max_bytes:
            break
    return "".join(chunks)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:9876/mcp")
    ap.add_argument("--host", required=True, help="host substring to filter the site map")
    ap.add_argument("--token", default=os.environ.get("REVOLT_MCP_TOKEN", ""))
    ap.add_argument("--in-scope-only", action="store_true")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--max-body", type=int, default=65536)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    headers = {"Authorization": f"Bearer {args.token}"} if args.token else None
    async with streamablehttp_client(args.url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            cursor, total, page_no = None, 0, 0
            while True:
                page_no += 1
                page = structured(await session.call_tool("get_site_map", {
                    "host": args.host,
                    "inScopeOnly": args.in_scope_only,
                    "limit": args.limit,
                    **({"cursor": cursor} if cursor else {}),
                }))
                rows = page.get("items", [])
                print(f"[page {page_no}] {len(rows)} rows "
                      f"(total={page.get('totalCount')}, hasMore={page.get('hasMore')})")
                for row in rows:
                    total += 1
                    print(f"  {row.get('status','---')} {row.get('method','?'):6} {row['url']}  "
                          f"({row.get('mimeType','?')}, {row.get('responseLength',0)}B)  id={row['id']}")
                    if args.out:
                        req = await fetch_body(session, row["id"], "request", args.max_body)
                        resp = await fetch_body(session, row["id"], "response", args.max_body)
                        save(args.out, row, req, resp)
                cursor = page.get("nextCursor")
                if not cursor:
                    break
            print(f"\nDone. {total} endpoint(s)." + (f" Saved under {args.out}/" if args.out else ""))


def save(out_dir, row, req, resp):
    os.makedirs(out_dir, exist_ok=True)
    safe = row["id"].replace(":", "_")
    with open(os.path.join(out_dir, f"{safe}.txt"), "w", encoding="utf-8") as f:
        f.write(f"# {row.get('method')} {row['url']} -> {row.get('status')}\n")
        f.write("\n===== REQUEST =====\n" + req + "\n\n===== RESPONSE =====\n" + resp + "\n")


if __name__ == "__main__":
    asyncio.run(main())
