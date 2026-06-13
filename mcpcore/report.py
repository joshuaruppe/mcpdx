"""Finding model and report renderers (console / JSON / Markdown)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List

# Severity ordering for sorting and exit codes.
SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

_SEV_COLOR = {
    "CRITICAL": ("\033[1m\033[97m\033[41m", "CRIT"),
    "HIGH": ("\033[1m\033[91m", "HIGH"),
    "MEDIUM": ("\033[1m\033[93m", "MED "),
    "LOW": ("\033[36m", "LOW "),
    "INFO": ("\033[90m", "INFO"),
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


@dataclass
class Finding:
    id: str                      # short stable code, e.g. RMCP-TP-001
    title: str
    severity: str                # CRITICAL/HIGH/MEDIUM/LOW/INFO
    category: str                # e.g. "tool-poisoning"
    target: str = ""             # tool/resource/prompt name or URI
    evidence: str = ""           # what was observed
    recommendation: str = ""     # remediation guidance
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.category, f.target))


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
#  Console                                                                     #
# --------------------------------------------------------------------------- #
def render_console(findings: List[Finding], color: bool = True) -> str:
    if not findings:
        return ("  " + _c("No findings.", "\033[92m", color))
    lines = []
    for f in sort_findings(findings):
        col, label = _SEV_COLOR.get(f.severity, ("", f.severity))
        sev = _c(f" {label} ", col, color)
        head = f"{sev} {_c(f.id, _BOLD, color)}  {f.title}"
        lines.append(head)
        if f.target:
            lines.append(f"        target : {f.target}")
        lines.append(f"        class  : {f.category}")
        if f.evidence:
            for i, chunk in enumerate(_wrap(f.evidence)):
                lines.append(f"        {'evidence:' if i == 0 else '         '} {chunk}")
        if f.recommendation:
            for i, chunk in enumerate(_wrap(f.recommendation)):
                lines.append(f"        {'fix     :' if i == 0 else '         '} {chunk}")
        lines.append("")
    return "\n".join(lines)


def render_summary(findings: List[Finding], color: bool = True) -> str:
    counts = severity_counts(findings)
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        col, _ = _SEV_COLOR[sev]
        n = counts[sev]
        txt = f"{sev}:{n}"
        parts.append(_c(txt, col, color) if n else _c(txt, "\033[90m", color))
    return "  " + "   ".join(parts)


# --------------------------------------------------------------------------- #
#  JSON / Markdown                                                             #
# --------------------------------------------------------------------------- #
def render_json(meta: dict, capabilities: dict, findings: List[Finding]) -> str:
    doc = {
        "tool": "mcpdx",
        "meta": meta,
        "surface": capabilities,
        "summary": severity_counts(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def render_markdown(meta: dict, capabilities: dict, findings: List[Finding]) -> str:
    out = ["# mcpdx (MCP Doctor) assessment report", ""]
    for k, v in meta.items():
        out.append(f"- **{k}**: {v}")
    out.append("")
    counts = severity_counts(findings)
    out.append("## Summary")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|----------|-------|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        out.append(f"| {sev} | {counts[sev]} |")
    out.append("")

    out.append("## Attack surface")
    out.append("")
    for kind in ("tools", "resources", "resourceTemplates", "prompts"):
        items = capabilities.get(kind, [])
        out.append(f"- **{kind}**: {len(items)}")
    out.append("")

    out.append("## Findings")
    out.append("")
    if not findings:
        out.append("_No findings._")
    for f in sort_findings(findings):
        out.append(f"### {f.severity} — {f.id}: {f.title}")
        out.append("")
        if f.target:
            out.append(f"- **Target**: `{f.target}`")
        out.append(f"- **Category**: {f.category}")
        if f.evidence:
            out.append(f"- **Evidence**: {f.evidence}")
        if f.recommendation:
            out.append(f"- **Recommendation**: {f.recommendation}")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
#  helpers                                                                     #
# --------------------------------------------------------------------------- #
def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color and code else text


def _wrap(text: str, width: int = 96):
    text = " ".join(str(text).split())
    if len(text) <= width:
        return [text]
    words, lines, cur = text.split(" "), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines
