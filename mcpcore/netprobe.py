"""Transport-layer probes: TLS posture, plaintext downgrade, and rate limiting.

Covers checklist §1 (TLS enforcement / version / ciphers) and §11/§12
(rate limiting, concurrency / resource exhaustion).

`TlsProbe` is read-only (one TLS handshake + one downgrade attempt) and runs in
`audit`/`scan`. `RateLimitProbe` generates a short burst of requests, so it runs
only in the active phase (`scan --active` / `fuzz`).
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse

from .client import MCPClient
from .report import Finding
from .transport import HttpTransport, TransportError

WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON")


class TlsProbe:
    def __init__(self, log, url, insecure=False, timeout=10.0):
        self.log = log
        self.url = url
        self.insecure = insecure
        self.timeout = timeout
        self.findings = []
        self._seq = 0

    def _add(self, **kw):
        self._seq += 1
        kw.setdefault("id", f"RMCP-T{self._seq:03d}")
        self.findings.append(Finding(**kw))

    def run(self):
        parsed = urlparse(self.url)
        if parsed.scheme == "https":
            self._inspect_tls(parsed)
        self._downgrade_test(parsed)
        return self.findings

    def _inspect_tls(self, parsed):
        host = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    version = ssock.version() or "?"
                    cipher = ssock.cipher() or ("?", "?", 0)
        except Exception as e:
            self.log.debug(f"TLS inspection failed: {e}")
            return
        name, _, bits = cipher
        self.log.debug(f"TLS {version}, cipher {name} ({bits} bits)")
        weak = (version in WEAK_TLS
                or (isinstance(bits, int) and bits and bits < 128)
                or any(tok in (name or "").upper() for tok in WEAK_CIPHER_TOKENS))
        if weak:
            self._add(
                title="Weak TLS version / cipher negotiated",
                severity="MEDIUM",
                category="transport-security",
                target=f"{host}:{port}",
                evidence=f"Negotiated {version} with cipher {name} ({bits} bits).",
                recommendation="Require TLS 1.2+ (prefer 1.3) and disable RC4/3DES/"
                               "export/anonymous ciphers.",
            )
        else:
            self._add(
                title="TLS posture",
                severity="INFO",
                category="transport-security",
                target=f"{host}:{port}",
                evidence=f"Negotiated {version} with cipher {name} ({bits} bits).",
                recommendation="",
            )

    def _downgrade_test(self, parsed):
        if parsed.scheme != "https":
            return  # already plaintext; handled by the static transport finding
        # Try the same endpoint over plaintext http on the same port and on 80.
        candidates = []
        if parsed.port:
            candidates.append(parsed._replace(scheme="http").geturl())
        netloc_80 = (parsed.hostname or "") + ":80"
        candidates.append(urlunparse(parsed._replace(scheme="http", netloc=netloc_80)))
        for http_url in dict.fromkeys(candidates):
            if self._initialize_ok(http_url):
                self._add(
                    title="Server also reachable over plaintext HTTP (downgrade)",
                    severity="HIGH",
                    category="transport-security",
                    target=http_url,
                    evidence=f"The MCP endpoint completed an initialize handshake over "
                             f"{http_url} — TLS is not enforced; traffic can be "
                             f"downgraded to cleartext.",
                    recommendation="Disable plaintext listeners; redirect/deny http:// "
                                   "and enforce HSTS.",
                )
                return

    def _initialize_ok(self, http_url) -> bool:
        t = HttpTransport(http_url, self.log, timeout=min(self.timeout, 6.0))
        try:
            t.start()
            MCPClient(t, self.log, timeout=min(self.timeout, 6.0)).initialize()
            return True
        except Exception:
            return False
        finally:
            try:
                t.close()
            except Exception:
                pass


class RateLimitProbe:
    def __init__(self, log, url, headers, insecure=False, timeout=10.0, burst=15):
        self.log = log
        self.url = url
        self.headers = dict(headers or {})
        self.insecure = insecure
        self.timeout = timeout
        self.burst = burst
        self.findings = []

    def run(self):
        self.log.info(f"rate-limit probe: {self.burst} concurrent initialize requests")
        results = {"ok": 0, "throttled": 0, "error": 0}

        def one(_i):
            t = HttpTransport(self.url, self.log, headers=self.headers,
                              insecure=self.insecure, timeout=self.timeout)
            try:
                t.start()
                client = MCPClient(t, self.log, timeout=self.timeout)
                client.initialize()
                return "ok"
            except Exception as e:
                msg = str(e)
                return "throttled" if ("429" in msg or "rate" in msg.lower()) else "error"
            finally:
                try:
                    t.close()
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=min(self.burst, 16)) as ex:
            futures = [ex.submit(one, i) for i in range(self.burst)]
            for f in as_completed(futures):
                results[f.result()] = results.get(f.result(), 0) + 1

        self.log.debug(f"rate-limit results: {results}")
        if results["throttled"] > 0:
            self.findings.append(Finding(
                id="RMCP-R001",
                title="Rate limiting observed",
                severity="INFO",
                category="rate-limiting",
                target=self.url,
                evidence=f"{results['throttled']}/{self.burst} burst requests were "
                         f"throttled (429 / rate-limit).",
                recommendation="",
            ))
        elif results["ok"] >= self.burst:
            self.findings.append(Finding(
                id="RMCP-R001",
                title="No rate limiting on tool/session creation",
                severity="MEDIUM",
                category="rate-limiting",
                target=self.url,
                evidence=f"All {self.burst} concurrent initialize requests succeeded with "
                         f"no throttling — the server is exposed to prompt-storm / "
                         f"resource-exhaustion (DoS) techniques.",
                recommendation="Enforce per-client rate limits and concurrency caps on "
                               "session creation and tool invocation.",
            ))
        return self.findings
