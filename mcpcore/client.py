"""MCP / JSON-RPC 2.0 client built on top of a transport.

Handles the initialize handshake, request/response correlation, pagination,
and the common MCP methods a pentester enumerates and exercises.
"""

from __future__ import annotations

import itertools
from typing import Any, Dict, List, Optional

from .transport import BaseTransport, TransportError

PROTOCOL_VERSION = "2025-11-25"


class RpcError(Exception):
    def __init__(self, code, message, data=None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data


class MCPClient:
    def __init__(self, transport: BaseTransport, log, timeout: float = 30.0):
        self.t = transport
        self.log = log
        self.timeout = timeout
        self._ids = itertools.count(1)
        self.server_info: Dict[str, Any] = {}
        self.capabilities: Dict[str, Any] = {}
        self.protocol_version: Optional[str] = None
        self.instructions: Optional[str] = None
        self._pending: Dict[Any, dict] = {}

    # -- low level ------------------------------------------------------------
    def request(self, method: str, params: Optional[dict] = None) -> Any:
        rid = next(self._ids)
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.log.debug(f"--> {method} (id={rid})")
        self.t.send_message(msg)
        return self._await_response(rid)

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.log.debug(f"--> {method} (notification)")
        self.t.send_message(msg)

    def _await_response(self, rid) -> Any:
        # Drain queue until our id shows up; stash/handle anything else.
        if rid in self._pending:
            return self._unwrap(self._pending.pop(rid))
        while True:
            msg = self.t.read_message(timeout=self.timeout)
            if msg is None:
                raise TransportError(f"timed out waiting for response to id={rid}")
            mid = msg.get("id")
            if mid == rid:
                return self._unwrap(msg)
            if mid is not None and ("result" in msg or "error" in msg):
                self._pending[mid] = msg  # response to a different request
            elif msg.get("method"):
                self._handle_server_message(msg)
            else:
                self.log.debug(f"ignoring unexpected message: {str(msg)[:120]}")

    def _unwrap(self, msg: dict) -> Any:
        if "error" in msg:
            err = msg["error"]
            raise RpcError(err.get("code"), err.get("message", ""), err.get("data"))
        return msg.get("result")

    def _handle_server_message(self, msg: dict) -> None:
        method = msg.get("method", "")
        # Server -> client requests we must answer to keep the session alive.
        if method == "ping" and msg.get("id") is not None:
            self.t.send_message({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
        elif method in ("roots/list",) and msg.get("id") is not None:
            self.t.send_message({"jsonrpc": "2.0", "id": msg["id"], "result": {"roots": []}})
        else:
            self.log.debug(f"server notification: {method}")

    # -- handshake ------------------------------------------------------------
    def initialize(self, client_name="mcpdx", client_version="1.0.0") -> dict:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                "clientInfo": {"name": client_name, "version": client_version},
            },
        )
        self.server_info = result.get("serverInfo", {})
        self.capabilities = result.get("capabilities", {})
        self.protocol_version = result.get("protocolVersion")
        self.instructions = result.get("instructions")
        self.notify("notifications/initialized")
        return result

    # -- enumeration ----------------------------------------------------------
    def _list_paginated(self, method: str, key: str) -> List[dict]:
        items: List[dict] = []
        cursor = None
        for _ in range(100):  # hard cap to avoid a hostile infinite paginator
            params = {"cursor": cursor} if cursor else {}
            try:
                result = self.request(method, params)
            except RpcError as e:
                self.log.debug(f"{method} not supported / errored: {e}")
                return items
            items.extend(result.get(key, []))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return items

    def list_tools(self) -> List[dict]:
        return self._list_paginated("tools/list", "tools")

    def list_resources(self) -> List[dict]:
        return self._list_paginated("resources/list", "resources")

    def list_resource_templates(self) -> List[dict]:
        return self._list_paginated("resources/templates/list", "resourceTemplates")

    def list_prompts(self) -> List[dict]:
        return self._list_paginated("prompts/list", "prompts")

    # -- invocation -----------------------------------------------------------
    def call_tool(self, name: str, arguments: Optional[dict] = None) -> Any:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def read_resource(self, uri: str) -> Any:
        return self.request("resources/read", {"uri": uri})

    def get_prompt(self, name: str, arguments: Optional[dict] = None) -> Any:
        return self.request("prompts/get", {"name": name, "arguments": arguments or {}})
