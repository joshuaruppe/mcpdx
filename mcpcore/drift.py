"""Capability-drift / rug-pull detection.

Addresses the NSA MCP-security concerns that a *trusted* server can change its
advertised capabilities without re-approval, and the documented pattern of a
server advertising benign tool definitions at first and swapping in malicious
ones after a few uses (e.g. the WhatsApp MCP exfiltration case).

How it works:
  * `build_manifest()` snapshots the declared surface, hashing each tool /
    prompt / resource definition.
  * `DriftDetector` diffs a current surface against a saved manifest (baseline)
    or an earlier in-session snapshot, emitting findings for added / removed /
    changed capabilities. Changed text is re-run through the poisoning and
    hidden-Unicode scanners so a description that *mutates* into an injection
    payload is flagged HIGH.

This detects drift you actually observe. It cannot prove the *absence* of a
server-side rug pull that only triggers for a different identity, environment,
or real-world condition you don't reproduce — reflect that in reporting.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List

from . import payloads
from .report import Finding

KINDS = [
    ("tool", "tools", "name"),
    ("prompt", "prompts", "name"),
    ("resource", "resources", "uri"),
    ("resourceTemplate", "resourceTemplates", "uriTemplate"),
]


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash(obj) -> str:
    return hashlib.sha256(_canon(obj).encode("utf-8")).hexdigest()[:16]


def manifest_items(surface: dict) -> Dict[str, dict]:
    """Map 'kind:id' -> {hash, definition} for every item in a surface."""
    items: Dict[str, dict] = {}
    for kind, skey, idfield in KINDS:
        for item in surface.get(skey, []) or []:
            ident = item.get(idfield, "<unknown>")
            items[f"{kind}:{ident}"] = {"hash": _hash(item), "definition": item}
    return items


def build_manifest(surface: dict, session: dict, captured_at: str = "") -> dict:
    return {
        "tool": "mcpdx",
        "schema": 1,
        "captured_at": captured_at,
        "target": session.get("target"),
        "transport": session.get("transport"),
        "server": session.get("server_info", {}),
        "protocol": session.get("protocol_version"),
        "items": manifest_items(surface),
    }


class DriftDetector:
    def __init__(self, log):
        self.log = log
        self.findings: List[Finding] = []
        self._seq = 0
        self._seen = set()  # dedup change-signatures across repeated comparisons

    def _add(self, **kw) -> None:
        self._seq += 1
        kw.setdefault("id", f"RMCP-D{self._seq:03d}")
        self.findings.append(Finding(**kw))

    # -- public comparisons ---------------------------------------------------
    def compare_manifest(self, baseline: dict, current_surface: dict,
                         label: str = "baseline") -> List[Finding]:
        old = baseline.get("items", {}) or {}
        before = self._diff(old, manifest_items(current_surface), label)
        return self.findings[before:]

    def compare_surface(self, old_surface: dict, new_surface: dict,
                        label: str = "watch") -> List[Finding]:
        before = self._diff(manifest_items(old_surface),
                            manifest_items(new_surface), label)
        return self.findings[before:]

    # -- core diff ------------------------------------------------------------
    def _diff(self, old: Dict[str, dict], new: Dict[str, dict], label: str) -> int:
        start = len(self.findings)
        old_keys, new_keys = set(old), set(new)

        for k in sorted(new_keys - old_keys):
            sig = ("add", k, new[k]["hash"])
            if sig in self._seen:
                continue
            self._seen.add(sig)
            self._report_added(k, new[k]["definition"], label)

        for k in sorted(old_keys - new_keys):
            sig = ("del", k, old[k]["hash"])
            if sig in self._seen:
                continue
            self._seen.add(sig)
            self._add(
                title="Capability removed since snapshot",
                severity="LOW",
                category="capability-drift",
                target=k,
                evidence=f"{k} was present in the {label} but is no longer advertised.",
                recommendation="Confirm the removal is expected; disappearing/reappearing "
                               "capabilities can mask conditional (rug-pull) behaviour.",
                metadata={"label": label},
            )

        for k in sorted(old_keys & new_keys):
            if old[k]["hash"] == new[k]["hash"]:
                continue
            sig = ("chg", k, old[k]["hash"], new[k]["hash"])
            if sig in self._seen:
                continue
            self._seen.add(sig)
            self._report_changed(k, old[k]["definition"], new[k]["definition"], label)
        return start

    # -- finding builders -----------------------------------------------------
    def _report_added(self, key, definition, label) -> None:
        sev, notes = self._poison_check(definition)
        base = "HIGH" if sev == "HIGH" else "MEDIUM"
        note = f" ({'; '.join(notes)})" if notes else ""
        self._add(
            title="New capability appeared since snapshot",
            severity=base,
            category="capability-drift",
            target=key,
            evidence=f"{key} was not present in the {label} and is now advertised{note}. "
                     f"A trusted server gaining capabilities without re-approval is a "
                     f"rug-pull indicator.",
            recommendation="Require explicit re-approval when a connected server's "
                           "capability set changes; pin/verify tool definitions.",
            metadata={"label": label},
        )

    def _report_changed(self, key, old_def, new_def, label) -> None:
        changed_fields = sorted(
            f for f in set(old_def) | set(new_def) if old_def.get(f) != new_def.get(f)
        )
        sev, notes = self._poison_check(new_def)

        oa = old_def.get("annotations") or {}
        na = new_def.get("annotations") or {}
        if not oa.get("destructiveHint") and na.get("destructiveHint"):
            sev = "HIGH"; notes.append("became destructive")
        if oa.get("readOnlyHint") and not na.get("readOnlyHint"):
            sev = "HIGH"; notes.append("readOnly hint removed")
        if "inputSchema" in changed_fields and sev != "HIGH":
            sev = "MEDIUM"; notes.append("input schema changed (possible widening)")
        if sev == "INFO":
            sev = "MEDIUM"

        ev = [f"{key} definition changed since the {label}; fields: {changed_fields}."]
        od, nd = old_def.get("description"), new_def.get("description")
        if od != nd:
            ev.append(f"description: {self._snip(od)!r} -> {self._snip(nd)!r}")
        if notes:
            ev.append("flags: " + "; ".join(notes))

        self._add(
            title="Capability definition changed since snapshot",
            severity=sev,
            category="capability-drift",
            target=key,
            evidence=" ".join(ev),
            recommendation="Treat post-approval definition changes as suspicious; "
                           "re-review and require re-consent. If text now contains "
                           "injection markers, handle as tool poisoning.",
            metadata={"label": label, "changed_fields": changed_fields},
        )

    # -- helpers --------------------------------------------------------------
    @staticmethod
    def _poison_check(definition):
        text = f"{definition.get('name', '')} {definition.get('description', '')}"
        notes = []
        sev = "INFO"
        if payloads.match_injection_markers(text):
            sev = "HIGH"; notes.append("contains injection-like phrasing")
        if payloads.find_invisible(text):
            sev = "HIGH"; notes.append("contains hidden/invisible Unicode")
        return sev, notes

    @staticmethod
    def _snip(text, n=80):
        if text is None:
            return None
        text = " ".join(str(text).split())
        return text[:n] + ("…" if len(text) > n else "")
