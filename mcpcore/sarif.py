"""SARIF 2.1.0 renderer (GitHub Code Scanning).

SARIF output is consumed *offline* — a CI step uploads the file to GitHub Code
Scanning (or another SARIF viewer) after the scan has run. It is therefore kept
separate from the live scanners: `mcpdx audit/scan --sarif` writes it inline, and
`mcpdx report SAVED.json --sarif OUT` regenerates it later from a stored JSON
report without touching the target again.

Findings are produced by the auditor/fuzzer (see `report.Finding`); this module
only formats them.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, List

from . import __version__
from .report import Finding, SEVERITY_ORDER, severity_counts, sort_findings

# SARIF result levels and GitHub Code Scanning security-severity buckets.
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}
_SARIF_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0",
                            "LOW": "3.0", "INFO": "0.0"}


def render_sarif(meta: dict, capabilities: dict, findings: List[Finding]) -> str:
    """Render findings as a SARIF 2.1.0 log.

    Rules are keyed by finding *category* (a stable, semantic id) rather than the
    per-run sequential finding id. Because mcpdx audits a live server's declared
    surface, not files in a repo, each result is anchored with a SARIF
    `logicalLocation` (the target identifier) plus a sanitized synthetic
    `artifactLocation` URI so SARIF viewers and GitHub Code Scanning still ingest
    it.
    """
    ordered = sort_findings(findings)

    # One rule per category; remember the worst severity seen for each.
    cat_severity: Dict[str, str] = {}
    for f in ordered:
        prev = cat_severity.get(f.category)
        if prev is None or SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(prev, 0):
            cat_severity[f.category] = f.severity
    rule_index = {cat: i for i, cat in enumerate(cat_severity)}

    rules = []
    for cat, sev in cat_severity.items():
        rules.append({
            "id": cat,
            "name": _rule_name(cat),
            "shortDescription": {"text": _humanize(cat)},
            "fullDescription": {"text": f"{_humanize(cat)} findings reported by mcpdx."},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(sev, "warning")},
            "properties": {
                "security-severity": _SARIF_SECURITY_SEVERITY.get(sev, "5.0"),
                "tags": ["security", "mcp"],
            },
        })

    results = []
    for f in ordered:
        text = f"{f.title}."
        if f.target:
            text += f" Target: {f.target}."
        if f.evidence:
            text += f" {f.evidence}"
        if f.recommendation:
            text += f" Fix: {f.recommendation}"
        results.append({
            "ruleId": f.category,
            "ruleIndex": rule_index[f.category],
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.target)},
                },
                "logicalLocations": [{
                    "fullyQualifiedName": f.target or "mcp-server",
                    "kind": "resource",
                }],
            }],
            "partialFingerprints": {"mcpdxFinding/v1": _fingerprint(f)},
            "properties": {
                "id": f.id,
                "severity": f.severity,
                "security-severity": _SARIF_SECURITY_SEVERITY.get(f.severity, "5.0"),
                "category": f.category,
                "target": f.target,
            },
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mcpdx",
                "fullName": "mcpdx (MCP Doctor)",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": rules,
            }},
            "automationDetails": {"id": f"mcpdx/{meta.get('target', '')}"},
            "results": results,
            "properties": {
                "target": meta.get("target"),
                "server": meta.get("server"),
                "protocol": meta.get("protocol"),
                "summary": severity_counts(findings),
            },
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
#  helpers                                                                     #
# --------------------------------------------------------------------------- #
def _humanize(category: str) -> str:
    return re.sub(r"[-_]+", " ", category).strip().capitalize() or "Finding"


def _rule_name(category: str) -> str:
    parts = re.split(r"[-_\s]+", category)
    return "".join(p[:1].upper() + p[1:] for p in parts if p) or "Finding"


def _uri(target: str) -> str:
    if not target:
        return "mcp-server"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_")
    return safe or "mcp-server"


def _fingerprint(f: Finding) -> str:
    digest = hashlib.sha256(f"{f.category}|{f.target}|{f.title}".encode("utf-8"))
    return digest.hexdigest()[:16]
