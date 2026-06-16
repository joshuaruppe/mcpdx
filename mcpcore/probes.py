"""Active access-control and session-security probes (HTTP transport).

These address NSA MCP-security concerns around **access control** ("many
implementations omit authentication entirely") and **token/session security**
("session hijacking… unauthorized reuse of valid sessions").

The probes are read-only — they only attempt `initialize` + `tools/list` — but
they DO open additional connections, so they run as part of an authorized
assessment. They are HTTP-only; local servers inherit the trust of the spawning
process and have no network auth boundary to test.
"""

from __future__ import annotations

from typing import List, Tuple

from .client import MCPClient, RpcError
from .report import Finding
from .transport import HttpTransport, TransportError

AUTH_HEADERS = {"authorization", "x-api-key", "api-key", "apikey", "cookie", "x-auth-token"}
FORGED_SESSION_ID = "mcpdx-forged-session-000000000000"


class AuthSessionProbe:
    def __init__(self, log, url, headers, insecure=False, timeout=15.0):
        self.log = log
        self.url = url
        self.headers = dict(headers or {})
        self.insecure = insecure
        self.timeout = timeout
        self.findings: List[Finding] = []
        self._seq = 0

    def _add(self, **kw) -> None:
        self._seq += 1
        kw.setdefault("id", f"RMCP-P{self._seq:03d}")
        self.findings.append(Finding(**kw))

    # -- entrypoint -----------------------------------------------------------
    def run(self) -> List[Finding]:
        self.log.info("running access-control / session probes (HTTP)")
        has_auth = any(k.lower() in AUTH_HEADERS for k in self.headers)
        self._probe_auth_boundary(has_auth)
        self._probe_session_validation()
        self.log.ok(f"probes complete: {len(self.findings)} finding(s)")
        return self.findings

    # -- auth boundary --------------------------------------------------------
    def _probe_auth_boundary(self, has_auth: bool) -> None:
        if not has_auth:
            self.log.debug("no credentials supplied; auth-boundary delta test skipped")
            return
        stripped = {k: v for k, v in self.headers.items() if k.lower() not in AUTH_HEADERS}
        ok, n_tools, detail = self._try_enumerate(stripped, do_init=True)
        if ok:
            self._add(
                title="Access control not enforced — enumerable without credentials",
                severity="HIGH",
                category="access-control",
                target=self.url,
                evidence=f"After stripping auth headers ({sorted(self.headers)}), the "
                         f"server still completed initialize and returned {n_tools} "
                         f"tool(s). Authentication appears optional/unenforced.",
                recommendation="Require and verify authentication on every request; "
                               "reject unauthenticated initialize/tools/list. Add "
                               "Origin validation to prevent DNS-rebinding.",
            )
        else:
            self._add(
                title="Authentication enforced on enumeration",
                severity="INFO",
                category="access-control",
                target=self.url,
                evidence=f"Unauthenticated enumeration was rejected ({detail}).",
                recommendation="",
            )

    # -- session validation ---------------------------------------------------
    def _probe_session_validation(self) -> None:
        # Send a request bearing a never-issued session ID, skipping initialize.
        # If the server honours it, session binding/validation is weak.
        ok, n_tools, detail = self._try_enumerate(
            self.headers, do_init=False, session_id=FORGED_SESSION_ID
        )
        if ok:
            self._add(
                title="Weak session validation — forged session ID accepted",
                severity="MEDIUM",
                category="session-security",
                target=self.url,
                evidence=f"A request carrying an unissued Mcp-Session-Id "
                         f"('{FORGED_SESSION_ID}') and no initialize handshake was "
                         f"honoured ({n_tools} tool(s) returned). Sessions are not "
                         f"bound to a verified initialize/identity.",
                recommendation="Issue unguessable session IDs server-side, bind them to "
                               "an authenticated identity, and reject requests with "
                               "unknown/expired IDs (lifecycle + revocation).",
            )
        else:
            self._add(
                title="Forged session ID rejected",
                severity="INFO",
                category="session-security",
                target=self.url,
                evidence=f"Request with an unissued session ID was rejected ({detail}).",
                recommendation="",
            )

    # -- helper ---------------------------------------------------------------
    def _try_enumerate(self, headers, do_init=True, session_id=None) -> Tuple[bool, int, str]:
        """Attempt a minimal enumeration; return (succeeded, n_tools, detail)."""
        t = HttpTransport(self.url, self.log, headers=headers,
                          insecure=self.insecure, timeout=self.timeout)
        try:
            t.start()
            if session_id:
                t.session_id = session_id
            client = MCPClient(t, self.log, timeout=self.timeout)
            if do_init:
                client.initialize()
            tools = client.list_tools()
            return True, len(tools), "ok"
        except RpcError as e:
            return False, 0, f"{e}"
        except TransportError as e:
            return False, 0, f"transport: {e}"
        except Exception as e:
            return False, 0, f"{type(e).__name__}: {e}"
        finally:
            try:
                t.close()
            except Exception:
                pass
