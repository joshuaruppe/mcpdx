"""Active fuzzing of MCP tools and resources.

DANGER: this module *invokes* server tools with attack payloads. It can cause
side effects (writes, deletions, outbound requests, command execution) on the
target. It is gated behind an explicit --active flag and an authorization
acknowledgement in the CLI. Use only against systems you are authorized to test.

Strategy: for each tool, classify its parameters from the input schema, then
inject the relevant payload family into string parameters and inspect the
response for indicators of a vulnerable code path.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from . import payloads
from .client import MCPClient, RpcError
from .report import Finding


class Fuzzer:
    def __init__(self, client: MCPClient, log, max_payloads: Optional[int] = None,
                 include_robustness: bool = True):
        self.client = client
        self.log = log
        self.findings: List[Finding] = []
        self.max_payloads = max_payloads
        self.include_robustness = include_robustness
        self._seq = 0

    def _add(self, **kw) -> None:
        self._seq += 1
        kw.setdefault("id", f"RMCP-F{self._seq:03d}")
        self.findings.append(Finding(**kw))

    # -- entrypoint -----------------------------------------------------------
    def run(self, surface: Dict[str, Any]) -> List[Finding]:
        tools = surface.get("tools", [])
        self.log.warn(f"ACTIVE fuzzing {len(tools)} tool(s) — this WILL invoke them")
        for tool in tools:
            self._fuzz_tool(tool)
        self.log.ok(f"active fuzzing complete: {len(self.findings)} finding(s)")
        return self.findings

    # -- per tool -------------------------------------------------------------
    def _fuzz_tool(self, tool: dict) -> None:
        name = tool.get("name")
        if not name:
            return
        schema = tool.get("inputSchema", {}) or {}

        # Treat live tool OUTPUT as untrusted: scan a benign baseline response
        # for injected instructions, hidden Unicode, leaked secrets, and schema
        # drift. Done first so it also covers tools with no string params.
        self._inspect_output(tool)

        # Object-param probes (NoSQL / prototype pollution) are independent of
        # string params, so run them before the string-param early-return.
        self._inject_object_params(name, schema)

        str_params = self._string_params(schema)
        if not str_params:
            self.log.debug(f"tool '{name}' has no string params; skipping injection")
            return

        # Baseline (no-payload) response for differential detection: an indicator
        # that already fires on the benign baseline — e.g. a tool that naturally
        # returns "49" — must NOT be attributed to a payload. This is what keeps
        # the always-on SSTI 7*7=49 canary from false-flagging ordinary tools.
        baseline_text = self._safe_call(name, self._baseline_args(schema)) or ""

        classes = payloads.match_capability(name, tool.get("description", "") or "")

        families = []
        if "filesystem" in classes or not classes:
            families.append(("path-traversal", payloads.PATH_TRAVERSAL,
                             payloads.PATH_TRAVERSAL_INDICATORS, "HIGH"))
        if "code_execution" in classes or not classes:
            families.append(("command-injection", payloads.COMMAND_INJECTION,
                             payloads.COMMAND_INJECTION_INDICATORS, "CRITICAL"))
        if "network" in classes or not classes:
            families.append(("ssrf", payloads.SSRF + payloads.URI_SCHEMES,
                             payloads.SSRF_INDICATORS + payloads.PATH_TRAVERSAL_INDICATORS,
                             "HIGH"))
        if "database" in classes or not classes:
            families.append(("sql-injection", payloads.SQL_INJECTION,
                             payloads.SQL_INJECTION_INDICATORS, "HIGH"))
        # SSTI can lurk in any text field, so always try it.
        families.append(("template-injection", payloads.SSTI,
                         payloads.SSTI_INDICATORS, "HIGH"))

        for fam_name, fam_payloads, indicators, sev in families:
            self._inject_family(name, schema, str_params, fam_name,
                                fam_payloads, indicators, sev, baseline_text)

        if self.include_robustness:
            self._robustness(name, schema, str_params)

    def _inject_family(self, tool, schema, str_params, fam_name,
                       fam_payloads, indicators, sev, baseline_text="") -> None:
        plist = fam_payloads
        if self.max_payloads:
            plist = plist[: self.max_payloads]
        for target_param in str_params:
            for payload in plist:
                args = self._baseline_args(schema)
                args[target_param] = payload
                self.log.debug(f"[{fam_name}] {tool}({target_param}=…) <- {payload!r}")
                text = self._safe_call(tool, args)
                if text is None:
                    continue
                # Guard against false positives from tools that merely reflect
                # the payload back: strip the literal payload before matching,
                # so only genuinely *new* response content can trip a signature.
                probe = text.replace(str(payload), " ")
                # Differential: ignore any indicator that already fires on the
                # benign baseline response (the tool emits it regardless of our
                # payload), so only payload-attributable matches count.
                if any(rx.search(probe) and not rx.search(baseline_text)
                       for rx in indicators):
                    self._add(
                        title=f"{fam_name.replace('-', ' ').title()} indicator in response",
                        severity=sev,
                        category=fam_name,
                        target=f"tool:{tool}",
                        evidence=f"param '{target_param}' = {payload!r} produced a "
                                 f"response matching a {fam_name} signature: "
                                 f"{self._snippet(text)}",
                        recommendation="Validate/canonicalize this input and confine "
                                       "the operation; the payload reached a sensitive sink.",
                        metadata={"param": target_param, "payload": str(payload)},
                    )
                    # one confirmed hit per (param,family) is enough
                    break

    def _inject_object_params(self, tool, schema) -> None:
        """NoSQL operator + prototype-pollution probes for object-typed params.

        Detection is best-effort (error-based): a server-side error or info
        disclosure indicates the operator reached a backend. A clean response
        does NOT prove safety — these usually need manual confirmation.
        """
        props = (schema or {}).get("properties", {}) or {}
        obj_params = [p for p, s in props.items()
                      if isinstance(s, dict) and s.get("type") == "object"]
        if not obj_params:
            return
        cases = [("nosql-injection", payloads.NOSQL_OBJECTS),
                 ("prototype-pollution", payloads.PROTOTYPE_POLLUTION)]
        for target_param in obj_params:
            for fam_name, objs in cases:
                for payload in objs:
                    args = self._baseline_args(schema)
                    args[target_param] = payload
                    self.log.debug(f"[{fam_name}] {tool}({target_param}=…) <- {payload!r}")
                    text = self._safe_call(tool, args, expect_errors=True)
                    if not text:
                        continue
                    if any(rx.search(text) for rx in
                           payloads.SQL_INJECTION_INDICATORS + payloads.INFO_DISCLOSURE_INDICATORS):
                        self._add(
                            title=f"{fam_name.replace('-', ' ').title()} reached a backend",
                            severity="MEDIUM",
                            category=fam_name,
                            target=f"tool:{tool}",
                            evidence=f"object param '{target_param}' = {payload!r} produced "
                                     f"a backend error/disclosure: {self._snippet(text)}. "
                                     f"Confirm impact manually.",
                            recommendation="Reject operator objects / unexpected keys; "
                                           "validate against a strict schema and sanitize "
                                           "before use in queries or object merges.",
                            metadata={"param": target_param, "payload": str(payload)},
                        )
                        break

    def _robustness(self, tool, schema, str_params) -> None:
        target_param = str_params[0]
        for payload in payloads.ROBUSTNESS:
            args = self._baseline_args(schema)
            args[target_param] = payload
            text = self._safe_call(tool, args, expect_errors=True)
            if text is None:
                continue
            for rx in payloads.INFO_DISCLOSURE_INDICATORS:
                if rx.search(text):
                    self._add(
                        title="Information disclosure in tool error output",
                        severity="MEDIUM",
                        category="info-disclosure",
                        target=f"tool:{tool}",
                        evidence=f"param '{target_param}' = {self._snippet(repr(payload))} "
                                 f"leaked internals: {self._snippet(text)}",
                        recommendation="Return generic error messages; log details "
                                       "server-side only.",
                        metadata={"param": target_param},
                    )
                    return  # one disclosure finding per tool is plenty

    def _inspect_output(self, tool) -> None:
        """Single benign call; scan the output for poisoning, secrets, and
        schema mismatches (checklist §6, §7, §10)."""
        name = tool.get("name")
        schema = tool.get("inputSchema", {}) or {}
        raw = self._call_raw(name, self._baseline_args(schema))
        if raw is None:
            return
        text = self._result_text(raw)
        if not text and not isinstance(raw, dict):
            return

        invisible = payloads.find_invisible(text)
        if invisible:
            self._add(
                title="Hidden/invisible Unicode in tool output",
                severity="HIGH",
                category="output-poisoning",
                target=f"tool:{name}",
                evidence=f"Live output contains non-printing characters "
                         f"({', '.join(sorted(set(invisible)))}) — a downstream agent "
                         f"could ingest instructions invisible to a human.",
                recommendation="Treat tool output as untrusted; strip/normalize control "
                               "and tag-block Unicode before passing it downstream.",
            )
        markers = payloads.match_injection_markers(text)
        if markers:
            self._add(
                title="LLM-targeted instructions in tool output",
                severity="HIGH",
                category="output-poisoning",
                target=f"tool:{name}",
                evidence=f"Live output contains injection-like phrasing: "
                         f"{markers[:6]}{' …' if len(markers) > 6 else ''}. A downstream "
                         f"agent may misread this passive content as executable prompts.",
                recommendation="Filter/sandbox tool outputs in the pipeline; detect "
                               "indirect prompt injection before chaining outputs.",
            )
        secrets = payloads.scan_secrets(text)
        if secrets:
            kinds = ", ".join(sorted({lbl for lbl, _ in secrets}))
            self._add(
                title="Secret/credential disclosed in tool output",
                severity="CRITICAL",
                category="secret-exposure",
                target=f"tool:{name}",
                evidence=f"Output appears to contain {kinds}: "
                         f"{[s for _, s in secrets][:4]}.",
                recommendation="Never return secrets to the model/client; redact and "
                               "scope credentials, and audit what tools expose.",
                metadata={"kinds": kinds},
            )
        self._check_output_schema(name, tool.get("outputSchema"), raw)

    def _check_output_schema(self, name, out_schema, raw) -> None:
        if not isinstance(out_schema, dict):
            return
        structured = raw.get("structuredContent") if isinstance(raw, dict) else None
        if not isinstance(structured, dict):
            return
        declared = set((out_schema.get("properties") or {}).keys())
        actual = set(structured.keys())
        extra = actual - declared
        if extra and declared:
            self._add(
                title="Undocumented fields in tool output",
                severity="MEDIUM",
                category="schema-mismatch",
                target=f"tool:{name}",
                evidence=f"Returned structuredContent includes field(s) {sorted(extra)} "
                         f"not present in the declared outputSchema {sorted(declared)} — "
                         f"possible inadvertent data exposure.",
                recommendation="Return only declared fields; align outputSchema with "
                               "actual output and strip extras server-side.",
                metadata={"undocumented": sorted(extra)},
            )

    # -- helpers --------------------------------------------------------------
    def _safe_call(self, tool, args, expect_errors=False) -> Optional[str]:
        try:
            result = self.client.call_tool(tool, args)
        except RpcError as e:
            # protocol-level error carries data we still want to inspect
            return f"{e.message} {json.dumps(e.data) if e.data else ''}"
        except Exception as e:  # transport hiccup, keep fuzzing other payloads
            self.log.debug(f"call error on {tool}: {e}")
            return None
        return self._result_text(result)

    def _call_raw(self, tool, args):
        """Return the raw tools/call result dict (errors wrapped as a dict)."""
        try:
            return self.client.call_tool(tool, args)
        except RpcError as e:
            return {"content": [{"type": "text",
                                 "text": f"{e.message} {json.dumps(e.data) if e.data else ''}"}],
                    "isError": True}
        except Exception as e:
            self.log.debug(f"call error on {tool}: {e}")
            return None

    @staticmethod
    def _result_text(result: Any) -> str:
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        chunks = []
        if isinstance(result, dict):
            for item in result.get("content", []) or []:
                if isinstance(item, dict):
                    chunks.append(item.get("text") or item.get("data") or json.dumps(item))
            if result.get("isError"):
                chunks.append("[isError=true]")
            if not chunks:
                chunks.append(json.dumps(result))
        else:
            chunks.append(json.dumps(result))
        return "\n".join(str(c) for c in chunks)

    @staticmethod
    def _string_params(schema: dict) -> List[str]:
        props = (schema or {}).get("properties", {}) or {}
        return [p for p, s in props.items()
                if isinstance(s, dict) and s.get("type", "string") == "string"]

    @staticmethod
    def _baseline_args(schema: dict) -> Dict[str, Any]:
        """Fill required params with innocuous placeholder values."""
        args: Dict[str, Any] = {}
        props = (schema or {}).get("properties", {}) or {}
        required = (schema or {}).get("required", []) or []
        for p in required:
            spec = props.get(p, {}) if isinstance(props.get(p), dict) else {}
            t = spec.get("type", "string")
            if t == "string":
                args[p] = spec.get("default", "mcpdx")
            elif t in ("number", "integer"):
                args[p] = spec.get("default", 1)
            elif t == "boolean":
                args[p] = spec.get("default", False)
            elif t == "array":
                args[p] = spec.get("default", [])
            elif t == "object":
                args[p] = spec.get("default", {})
        return args

    @staticmethod
    def _snippet(text: str, n: int = 220) -> str:
        text = " ".join(str(text).split())
        return text[:n] + ("…" if len(text) > n else "")
