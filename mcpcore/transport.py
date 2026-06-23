"""Transports for talking JSON-RPC 2.0 to an MCP server.

Two transports are supported:

* ``LocalTransport``  -- spawn a local process and exchange newline-delimited
  JSON-RPC messages over its stdin/stdout (the most common MCP deployment).
* ``HttpTransport``   -- the "Streamable HTTP" transport: POST JSON-RPC to a
  single endpoint, parsing either a JSON body or an SSE (text/event-stream)
  body in response. Session continuity is handled via ``Mcp-Session-Id``.

Both expose the same minimal interface:
    start()                 -- bring the transport up
    send_message(obj)       -- send one JSON-RPC message (dict)
    read_message(timeout)   -- return the next inbound message, or None
    close()                 -- tear the transport down

A background reader feeds an inbox queue so the client can correlate
responses to request ids and surface server-initiated notifications.
"""

from __future__ import annotations

import json
import queue
import shlex
import subprocess
import threading
import urllib.error
import urllib.request
from typing import Optional


class TransportError(Exception):
    pass


class BaseTransport:
    def __init__(self, log):
        self.log = log
        self._inbox: "queue.Queue[dict]" = queue.Queue()
        self._closed = False

    # to be implemented by subclasses
    def start(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def send_message(self, obj: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def read_message(self, timeout: float = 30.0) -> Optional[dict]:
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    # shared helpers
    def _enqueue(self, obj: dict) -> None:
        if self.log.is_trace:
            self.log.trace("<- " + json.dumps(obj)[:2000])
        self._inbox.put(obj)


# --------------------------------------------------------------------------- #
#  local (spawned process)                                                     #
# --------------------------------------------------------------------------- #
class LocalTransport(BaseTransport):
    def __init__(self, command, log, env=None, cwd=None):
        super().__init__(log)
        if isinstance(command, str):
            command = shlex.split(command, posix=False)
        self.command = command
        self.env = env
        self.cwd = cwd
        self.proc: Optional[subprocess.Popen] = None
        self._reader: Optional[threading.Thread] = None
        self._stderr_reader: Optional[threading.Thread] = None

    def start(self) -> None:
        self.log.debug(f"spawning: {' '.join(self.command)}")
        try:
            self.proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env,
                cwd=self.cwd,
                bufsize=1,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as e:
            raise TransportError(f"command not found: {self.command[0]}") from e
        except OSError as e:
            raise TransportError(f"failed to spawn process: {e}") from e

        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()
        self._stderr_reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_reader.start()
        self.log.ok(f"local transport up (pid {self.proc.pid})")

    def _read_stdout(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Not JSON-RPC: most likely banner/log noise on stdout.
                self.log.debug(f"non-JSON stdout: {line[:200]}")
                continue
            self._enqueue(obj)
        self.log.debug("stdout reader: stream closed")

    def _read_stderr(self) -> None:
        assert self.proc and self.proc.stderr
        for line in self.proc.stderr:
            line = line.rstrip()
            if line:
                self.log.debug(self.log.c(f"[server stderr] {line}", ""))

    def send_message(self, obj: dict) -> None:
        if not self.proc or self.proc.poll() is not None or self.proc.stdin is None:
            raise TransportError("server process is not running")
        data = json.dumps(obj, ensure_ascii=False)
        if self.log.is_trace:
            self.log.trace("-> " + data[:2000])
        try:
            self.proc.stdin.write(data + "\n")
            self.proc.stdin.flush()
        # ValueError covers "I/O operation on closed file" (stdin closed under a
        # race with close()); surface all of these as a clean TransportError
        # rather than letting them escape as an "unexpected error".
        except (BrokenPipeError, ValueError, OSError) as e:
            raise TransportError(f"failed to write to server: {e}") from e

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.log.debug("local transport closed")


# --------------------------------------------------------------------------- #
#  Streamable HTTP                                                             #
# --------------------------------------------------------------------------- #
class HttpTransport(BaseTransport):
    def __init__(self, url, log, headers=None, insecure=False, timeout=30.0):
        super().__init__(log)
        self.url = url
        self.headers = dict(headers or {})
        self.insecure = insecure
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self._opener = self._build_opener()

    def _build_opener(self):
        handlers = []
        if self.insecure and self.url.lower().startswith("https"):
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
            self.log.warn("TLS certificate verification DISABLED (--insecure)")
        return urllib.request.build_opener(*handlers)

    def start(self) -> None:
        self.log.ok(f"http transport target: {self.url}")

    def send_message(self, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "mcpdx/1.0",
        }
        headers.update(self.headers)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id

        is_notification = "id" not in obj
        if self.log.is_trace:
            self.log.trace("-> " + json.dumps(obj)[:2000])

        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                # Capture session id handed back by the server on initialize.
                sid = resp.headers.get("Mcp-Session-Id")
                if sid and not self.session_id:
                    self.session_id = sid
                    self.log.debug(f"captured Mcp-Session-Id: {sid}")
                ctype = (resp.headers.get("Content-Type") or "").lower()
                raw = resp.read()
                if not raw:
                    return  # 202 Accepted for notifications, etc.
                if "text/event-stream" in ctype:
                    self._parse_sse(raw.decode("utf-8", "replace"))
                else:
                    self._parse_json_body(raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:500]
            except Exception:
                pass
            if is_notification:
                # No request id to correlate against; an enqueued error response
                # would just be an orphan nobody awaits. Log it and move on.
                self.log.debug(f"HTTP {e.code} {e.reason} on notification "
                               f"{obj.get('method')}")
            else:
                # Surface as a synthetic error response so the client/audit see it.
                self._enqueue({
                    "jsonrpc": "2.0",
                    "id": obj.get("id"),
                    "error": {"code": e.code, "message": f"HTTP {e.code} {e.reason}",
                              "data": detail},
                })
                self.log.warn(f"HTTP {e.code} {e.reason} on {obj.get('method')}")
        except urllib.error.URLError as e:
            raise TransportError(f"connection failed: {e.reason}") from e

    def _parse_json_body(self, text: str) -> None:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            self.log.debug(f"non-JSON HTTP body: {text[:200]}")
            return
        if isinstance(obj, list):
            for item in obj:
                self._enqueue(item)
        else:
            self._enqueue(obj)

    def _parse_sse(self, text: str) -> None:
        # Minimal SSE framing: events separated by blank lines; data lines join.
        for block in text.replace("\r\n", "\n").split("\n\n"):
            data_lines = [
                line[5:].lstrip() for line in block.split("\n")
                if line.startswith("data:")
            ]
            if not data_lines:
                continue
            payload = "\n".join(data_lines)
            try:
                self._enqueue(json.loads(payload))
            except json.JSONDecodeError:
                self.log.debug(f"non-JSON SSE data: {payload[:200]}")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Best-effort session teardown per the Streamable HTTP spec.
        if self.session_id:
            try:
                req = urllib.request.Request(
                    self.url,
                    headers={"Mcp-Session-Id": self.session_id, **self.headers},
                    method="DELETE",
                )
                self._opener.open(req, timeout=5)
                self.log.debug("sent session DELETE")
            except Exception:
                pass
