#!/usr/bin/env python3
"""Drive the programmatic Intruder (`intruder_attack`) over MCP Streamable-HTTP — zero dependencies.

    python examples/intruder_attack.py --host example.com --payloads "admin,root,test,' OR '1'='1"
    python examples/intruder_attack.py --host example.com \
        --template $'POST /login HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\nuser=§admin§&pw=§x§' \
        --attack clusterbomb --payload-sets "admin,root ; a,b,c"

Positions are marked with §…§ (the text between the markers is the base value). attack = sniper |
pitchfork | clusterbomb. Requires the server's "Allow mutating tools" switch ON; scope-confinement (if
enabled) must allow the host. ONLY run against targets you're authorized to test.
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
        resp = urllib.request.urlopen(req, timeout=120)
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
                                "clientInfo": {"name": "intruder", "version": "1.0"}})
        self.rpc("notifications/initialized", {}, notify=True)

    def call(self, name, args):
        res = self.rpc("tools/call", {"name": name, "arguments": args}).get("result", {})
        is_error = res.get("isError")
        text = (res.get("content", [{}]) or [{}])[0].get("text", "")
        data = json.loads(text) if text.startswith(("{", "[")) else {"text": text}
        return data, is_error


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:9876/mcp")
    ap.add_argument("--token", default=os.environ.get("REVOLT_MCP_TOKEN", ""))
    ap.add_argument("--host", required=True)
    ap.add_argument("--secure", action="store_true", default=True)
    ap.add_argument("--insecure", dest="secure", action="store_false")
    ap.add_argument("--template", default=None, help="raw request with §…§ markers (default: a query-param fuzz)")
    ap.add_argument("--attack", choices=["sniper", "pitchfork", "clusterbomb"], default="sniper")
    ap.add_argument("--payloads", default="admin,root,test,backup,'OR'1'='1", help="sniper payloads, comma-separated")
    ap.add_argument("--payload-file", default="", help="sniper: name of a server-side wordlist (see list_wordlists)")
    ap.add_argument("--payload-sets", default="", help="pitchfork/clusterbomb: lists separated by ';', items by ','")
    ap.add_argument("--payload-files", default="", help="pitchfork/clusterbomb: server-side wordlist names, comma-separated (one per position)")
    ap.add_argument("--list-wordlists", action="store_true", help="just list server-configured wordlists and exit")
    ap.add_argument("--max", type=int, default=200)
    args = ap.parse_args()

    template = args.template or f"GET /?q=§FUZZ§ HTTP/1.1\r\nHost: {args.host}\r\nConnection: close\r\n\r\n"

    tool_args = {"template": template, "attackType": args.attack, "host": args.host,
                 "secure": args.secure, "maxRequests": args.max}
    if args.attack == "sniper":
        if args.payload_file:
            tool_args["payloadFile"] = args.payload_file
        else:
            tool_args["payloads"] = [p for p in args.payloads.split(",") if p]
    else:
        if args.payload_files:
            tool_args["payloadFiles"] = [f.strip() for f in args.payload_files.split(",") if f.strip()]
        else:
            sets = [[i for i in grp.split(",") if i] for grp in args.payload_sets.split(";") if grp.strip()]
            if not sets:
                ap.error("provide --payload-sets or --payload-files for pitchfork/clusterbomb")
            tool_args["payloadSets"] = sets

    c = McpHttp(args.url, args.token)
    c.initialize()

    if args.list_wordlists:
        wl, _ = c.call("list_wordlists", {})
        print(f"== wordlists in {wl.get('dir')} ==")
        for f in wl.get("files", []):
            print(f"  {f['name']}  ({f['lines']} lines, {f['bytes']} bytes)")
        return

    print(f"== intruder_attack ({args.attack}) against {args.host} ==")
    res, err = c.call("intruder_attack", tool_args)
    if err:
        print("ERROR:", res.get("text") or res)
        print("(enable 'Allow mutating tools' in the Server tab; ensure the host is in scope if confinement is on)")
        return

    print(f"sent={res['sent']}  anomaly={res['anomaly']}")
    print("\n-- distinct outcomes (grouped) --")
    for g in res["distinctOutcomes"]:
        print(f"  status={g['status']} len={g['responseLength']} count={g['count']} id={g.get('representativeId')}")
    print("\n-- sample (anomalies first) --")
    for h in res["sample"][:15]:
        print(f"  {h['status']}  len={h['length']:6}  payloads={h['payloads']}")

    rep = next((g.get("representativeId") for g in res["distinctOutcomes"] if g.get("representativeId")), None)
    if rep:
        print(f"\n-- representative response ({rep}) meta --")
        meta, _ = c.call("get_http_message", {"id": rep, "part": "response", "section": "meta"})
        print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()
