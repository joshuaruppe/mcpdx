"""Static (passive) security audit of an MCP server's declared surface.

This module never invokes a tool. It reasons purely over the metadata the
server advertises during enumeration: tool/resource/prompt names, their
descriptions, and JSON-Schema input definitions. It is therefore safe to run
against any reachable server without side effects.
"""

from __future__ import annotations

from typing import Any, Dict, List

from . import payloads
from .report import Finding


class Auditor:
    def __init__(self, log):
        self.log = log
        self.findings: List[Finding] = []
        self._seq = 0

    def _add(self, **kw) -> None:
        self._seq += 1
        kw.setdefault("id", f"RMCP-{self._seq:03d}")
        self.findings.append(Finding(**kw))

    # -- entrypoint -----------------------------------------------------------
    def run(self, surface: Dict[str, Any], session: Dict[str, Any]) -> List[Finding]:
        self.log.info("running static audit of declared surface")
        self._audit_session(session)
        self._audit_tool_collisions(surface.get("tools", []))
        for tool in surface.get("tools", []):
            self._audit_tool(tool)
        for prompt in surface.get("prompts", []):
            self._audit_prompt(prompt)
        for res in surface.get("resources", []):
            self._audit_resource(res)
        for tmpl in surface.get("resourceTemplates", []):
            self._audit_resource_template(tmpl)
        self.log.ok(f"static audit complete: {len(self.findings)} finding(s)")
        return self.findings

    # -- session / transport level -------------------------------------------
    def _audit_session(self, session: Dict[str, Any]) -> None:
        if session.get("transport") == "http":
            if not session.get("tls"):
                self._add(
                    title="MCP server reachable over plaintext HTTP",
                    severity="HIGH",
                    category="transport-security",
                    target=session.get("url", ""),
                    evidence="Streamable HTTP endpoint served over http:// — JSON-RPC "
                             "traffic (including tokens/arguments) is unencrypted.",
                    recommendation="Serve the MCP endpoint over HTTPS/TLS only.",
                )
            if not session.get("auth_supplied"):
                self._add(
                    title="Server enumerated without authentication",
                    severity="MEDIUM",
                    category="authn",
                    target=session.get("url", ""),
                    evidence="initialize + tools/list succeeded with no Authorization "
                             "header or credentials supplied by the client.",
                    recommendation="Require authentication (e.g. OAuth bearer token) "
                                   "before exposing tools/resources, and validate the "
                                   "Origin header to prevent DNS-rebinding.",
                )
        # Informational: record the server identity.
        si = session.get("server_info", {})
        self._add(
            title="Server identity",
            severity="INFO",
            category="recon",
            target=f"{si.get('name', '?')} {si.get('version', '')}".strip(),
            evidence=f"protocol={session.get('protocol_version')}, "
                     f"capabilities={sorted(session.get('capabilities', {}).keys())}",
            recommendation="",
        )
        instr = session.get("instructions")
        if instr:
            self._scan_text_for_injection(
                instr, target="server.instructions", category="instruction-injection",
                what="server `instructions` field",
            )

        # Known-CVE / vulnerable-version flagging based on serverInfo.
        name = (si.get("name") or "").lower()
        version = si.get("version") or ""
        for vuln in payloads.KNOWN_VULNS:
            if not any(m in name for m in vuln["match"]):
                continue
            if vuln.get("version_lt") and not payloads.version_lt(version, vuln["version_lt"]):
                continue  # patched version
            self._add(
                title=f"Known-vulnerable component: {vuln['cve']}",
                severity=vuln["severity"],
                category="known-vulnerability",
                target=f"{si.get('name','?')} {version}".strip(),
                evidence=vuln["desc"],
                recommendation=vuln["fix"],
                metadata={"cve": vuln["cve"]},
            )

    # -- tool-name collision / shadowing (invocation-path confusion) ----------
    def _audit_tool_collisions(self, tools) -> None:
        seen = {}
        for t in tools:
            name = t.get("name") or ""
            # normalize away case and separators to catch look-alikes/squatting
            norm = "".join(ch for ch in name.lower() if ch.isalnum())
            seen.setdefault(norm, []).append(name)
        for norm, names in seen.items():
            if len(names) < 2:
                continue
            exact = len(set(names)) == 1
            self._add(
                title=("Duplicate tool name" if exact else "Colliding / look-alike tool names"),
                severity=("HIGH" if exact else "MEDIUM"),
                category="tool-collision",
                target=", ".join(sorted(set(names))),
                evidence=f"{len(names)} tools resolve to the same identifier "
                         f"'{norm}' ({sorted(set(names))}). Ambiguous resolution lets a "
                         f"malicious tool shadow/override a legitimate one "
                         f"(invocation-path confusion).",
                recommendation="Enforce unique, fully-qualified tool identifiers and a "
                               "strict resolution policy; reject duplicate/confusable names.",
            )

    # -- tools ----------------------------------------------------------------
    def _audit_tool(self, tool: dict) -> None:
        name = tool.get("name", "<unnamed>")
        desc = tool.get("description", "") or ""
        schema = tool.get("inputSchema", {}) or {}

        # 1) tool poisoning / prompt injection in description
        self._scan_text_for_injection(
            desc, target=f"tool:{name}", category="tool-poisoning",
            what="tool description",
        )
        # also scan the tool name itself + annotations
        self._scan_text_for_injection(
            name, target=f"tool:{name}", category="tool-poisoning",
            what="tool name", min_sev_only=True,
        )
        # 2025-11-25 added a separate human-facing `title`; clients may surface it
        # to the model/user, so it is a poisoning surface too.
        title = tool.get("title")
        if isinstance(title, str) and title and title != name:
            self._scan_text_for_injection(
                title, target=f"tool:{name}", category="tool-poisoning",
                what="tool title",
            )
        # Parameter `description` fields ride along into the model's context but
        # are easy for a reviewer to overlook — a documented tool-poisoning spot.
        self._scan_schema_descriptions(schema, f"tool:{name}")

        # 2) sensitive capability classification
        classes = payloads.match_capability(name, desc)
        if classes:
            sev = "HIGH" if classes & {"code_execution", "secrets"} else "MEDIUM"
            self._add(
                title=f"Sensitive capability exposed: {', '.join(sorted(classes))}",
                severity=sev,
                category="excessive-capability",
                target=f"tool:{name}",
                evidence=f"Tool '{name}' appears to provide {', '.join(sorted(classes))} "
                         f"functionality based on its name/description.",
                recommendation="Confirm this tool is intended for untrusted LLM "
                               "invocation; sandbox it, constrain inputs, and apply "
                               "least privilege / human-in-the-loop confirmation.",
            )

        # 3) schema permissiveness — unconstrained free-text params feeding
        #    a sensitive sink are the classic injection vector.
        loose = self._loose_string_params(schema)
        if loose and classes:
            self._add(
                title="Unconstrained string input to a sensitive tool",
                severity="MEDIUM",
                category="input-validation",
                target=f"tool:{name}",
                evidence=f"Parameter(s) {loose} are free-form strings (no enum/pattern/"
                         f"format/maxLength) on a {sorted(classes)} tool.",
                recommendation="Constrain inputs with JSON-Schema enum/pattern/format/"
                               "maxLength and validate server-side before use.",
            )

        # 4) no input schema at all
        if not schema or not schema.get("properties"):
            self._add(
                title="Tool declares no input schema",
                severity="LOW",
                category="input-validation",
                target=f"tool:{name}",
                evidence="No inputSchema.properties advertised — clients cannot "
                         "validate arguments and the server may accept arbitrary input.",
                recommendation="Publish a strict JSON-Schema for tool inputs.",
            )

        # 5) icon-source surface (MCP 2025-11-25 `icons[]` metadata)
        self._audit_icons(tool.get("icons"), f"tool:{name}")

        # 6) destructive operation advertised via tool annotations
        ann = tool.get("annotations", {}) or {}
        if ann.get("destructiveHint") and ann.get("readOnlyHint") is not True:
            self._add(
                title="Tool self-describes as destructive",
                severity="MEDIUM",
                category="excessive-capability",
                target=f"tool:{name}",
                evidence="annotations.destructiveHint=true — the tool can perform "
                         "irreversible changes.",
                recommendation="Gate behind explicit human confirmation and audit "
                               "logging; ensure the calling agent cannot invoke it "
                               "autonomously on untrusted input.",
            )

    # -- prompts --------------------------------------------------------------
    def _audit_prompt(self, prompt: dict) -> None:
        name = prompt.get("name", "<unnamed>")
        desc = prompt.get("description", "") or ""
        self._scan_text_for_injection(
            desc, target=f"prompt:{name}", category="prompt-injection",
            what="prompt description",
        )
        self._audit_icons(prompt.get("icons"), f"prompt:{name}")

    # -- resources ------------------------------------------------------------
    def _audit_resource(self, res: dict) -> None:
        uri = res.get("uri", "")
        desc = res.get("description", "") or ""
        self._scan_text_for_injection(
            desc, target=f"resource:{uri}", category="resource-injection",
            what="resource description",
        )
        self._audit_icons(res.get("icons"), f"resource:{uri}")

    def _audit_resource_template(self, tmpl: dict) -> None:
        uri = tmpl.get("uriTemplate", "")
        self._audit_icons(tmpl.get("icons"), f"resourceTemplate:{uri}")
        # A templated file/path resource is a path-traversal candidate.
        low = uri.lower()
        if any(k in low for k in ("file:", "{path}", "{file", "{name}", "/{")):
            self._add(
                title="Templated resource may allow path traversal",
                severity="MEDIUM",
                category="path-traversal",
                target=f"resourceTemplate:{uri}",
                evidence=f"URI template '{uri}' interpolates client-controlled "
                         f"segments into a resource path.",
                recommendation="Canonicalize and allow-list resolved paths; reject "
                               "'..', absolute paths, and alternate encodings. Test "
                               "actively with `mcpdx fuzz --active`.",
            )

    # -- shared scanners ------------------------------------------------------
    def _audit_icons(self, icons, target) -> None:
        for sev, reason, src in payloads.analyze_icons(icons):
            self._add(
                title="Risky icon source in advertised metadata",
                severity=sev,
                category="icon-source",
                target=target,
                evidence=f"icons[].src = {src!r}: {reason}.",
                recommendation="Only render icons from a trusted, same-origin source; "
                               "reject data:/file: URIs and SVG icons, or sanitize/"
                               "rasterize before display. Never auto-fetch off-origin "
                               "icon URLs from an untrusted server.",
            )

    def _scan_schema_descriptions(self, schema, target) -> None:
        """Recurse a JSON-Schema and scan every `description` for poisoning.

        Covers nested objects/arrays so instructions can't hide one level down
        (e.g. properties.filter.properties.q.description).
        """
        if not isinstance(schema, dict):
            return
        seen = 0
        stack = [(schema, "")]
        while stack and seen < 200:  # bound work on a hostile/huge schema
            node, path = stack.pop()
            seen += 1
            if not isinstance(node, dict):
                continue
            desc = node.get("description")
            if isinstance(desc, str) and desc:
                where = f"parameter '{path}' description" if path else "schema description"
                self._scan_text_for_injection(
                    desc, target=target, category="tool-poisoning", what=where,
                )
            for key in ("properties", "patternProperties", "$defs", "definitions"):
                sub = node.get(key)
                if isinstance(sub, dict):
                    for pname, spec in sub.items():
                        child = f"{path}.{pname}" if path else pname
                        stack.append((spec, child))
            for key in ("items", "additionalProperties", "contains"):
                sub = node.get(key)
                if isinstance(sub, dict):
                    stack.append((sub, f"{path}[]" if path else "[]"))
            for key in ("anyOf", "oneOf", "allOf"):
                for i, spec in enumerate(node.get(key, []) or []):
                    stack.append((spec, f"{path}/{key}{i}" if path else f"{key}{i}"))

    def _scan_text_for_injection(self, text, target, category, what, min_sev_only=False):
        if not text:
            return
        invisible = payloads.find_invisible(text)
        if invisible:
            self._add(
                title="Hidden/invisible Unicode in advertised text",
                severity="HIGH",
                category="tool-poisoning",
                target=target,
                evidence=f"{what} contains non-printing characters "
                         f"({', '.join(sorted(set(invisible)))}) — a vector for "
                         f"instructions invisible to a human reviewer.",
                recommendation="Strip/normalize advertised text; reject control and "
                               "tag-block Unicode in tool metadata.",
            )
        if min_sev_only:
            return
        markers = payloads.match_injection_markers(text)
        if markers:
            self._add(
                title="Possible LLM-targeted instructions in advertised text",
                severity="HIGH",
                category=category,
                target=target,
                evidence=f"{what} contains injection-like phrasing: "
                         f"{markers[:6]}{' …' if len(markers) > 6 else ''}",
                recommendation="Treat tool/prompt metadata as untrusted; do not let "
                               "advertised text steer the agent. Review for "
                               "tool-poisoning / data-exfiltration intent.",
            )
        links = payloads.MARKDOWN_LINK.findall(text)
        if links:
            self._add(
                title="Markdown links / URLs in advertised text",
                severity="MEDIUM",
                category="tool-poisoning",
                target=target,
                evidence=f"{what} contains markdown formatting / URLs "
                         f"({links[:4]}{' …' if len(links) > 4 else ''}). An LLM that "
                         f"renders this can be steered to attacker-controlled links.",
                recommendation="Strip or plain-text advertised metadata; do not render "
                               "tool-supplied markdown to the model or user.",
            )

    @staticmethod
    def _loose_string_params(schema: dict) -> List[str]:
        loose = []
        props = (schema or {}).get("properties", {}) or {}
        for pname, spec in props.items():
            if not isinstance(spec, dict):
                continue
            if spec.get("type") == "string" and not any(
                k in spec for k in ("enum", "pattern", "format", "maxLength")
            ):
                loose.append(pname)
        return loose
