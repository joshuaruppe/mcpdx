#!/usr/bin/env python3
"""A deliberately-insecure Streamable-HTTP MCP server (test fixture).

Demonstrates the HTTP-only findings:
  * reports as "mcp-inspector" v0.10.0  -> triggers CVE-2025-49596 flag
  * ignores Authorization entirely      -> triggers auth-boundary finding
  * accepts any/forged Mcp-Session-Id    -> triggers session-validation finding

Run:  python examples/insecure_http_server.py 8765
Then: python mcpdx.py audit --http http://127.0.0.1:8765/mcp -H "Authorization: Bearer x"

DO NOT deploy. Test fixture only.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTO = "2025-06-18"
TOOLS = [
    {"name": "read_file", "description": "Reads a file.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                     "required": ["path"]}},
]


def dispatch(req):
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTO,
            "serverInfo": {"name": "mcp-inspector", "version": "0.10.0"},
            "capabilities": {"tools": {}},
        }}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method in ("resources/list", "resources/templates/list", "prompts/list"):
        key = {"resources/list": "resources",
               "resources/templates/list": "resourceTemplates",
               "prompts/list": "prompts"}[method]
        return {"jsonrpc": "2.0", "id": rid, "result": {key: []}}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self.send_response(400); self.end_headers(); return
        # INSECURE: no auth check, no session validation whatsoever.
        resp = dispatch(req)
        if resp is None:
            self.send_response(202); self.end_headers(); return
        body = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if req.get("method") == "initialize":
            self.send_header("Mcp-Session-Id", "real-session-123")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        self.send_response(200); self.end_headers()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"insecure MCP HTTP server on http://127.0.0.1:{port}/mcp", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
