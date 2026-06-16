#!/usr/bin/env python3
"""mcpdx (MCP Doctor) — MCP server security assessment toolkit.

A pentester's companion for *authorized* testing of Model Context Protocol
(MCP) servers. Connects to a local (spawned) server or a Streamable HTTP
endpoint, enumerates the exposed attack surface, performs a static security
audit, and — only when explicitly authorized — actively fuzzes tool inputs.

Examples
--------
  # Enumerate a local server
  python mcpdx.py enum --local "npx -y @modelcontextprotocol/server-filesystem ./data"

  # Static audit of a remote HTTP server, verbose, write a markdown report
  python mcpdx.py audit --http https://mcp.example.com/mcp -v --md report.md

  # Full assessment incl. ACTIVE fuzzing (requires authorization ack)
  python mcpdx.py scan --local "python my_server.py" --active --md report.md

  # Manually invoke a single tool
  python mcpdx.py call --local "python my_server.py" --tool read_file \
        --args '{"path":"README.md"}'
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import time

# Allow running both as `python mcpdx.py` and from elsewhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Make Unicode in the banner/findings safe on legacy (cp1252) Windows consoles.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from mcpcore import __version__
from mcpcore.audit import Auditor
from mcpcore.client import MCPClient, RpcError
from mcpcore import drift as drift_mod
from mcpcore.drift import DriftDetector
from mcpcore.fuzz import Fuzzer
from mcpcore.log import Logger
from mcpcore.netprobe import RateLimitProbe, TlsProbe
from mcpcore.probes import AuthSessionProbe
from mcpcore import report as R
from mcpcore import sarif
from mcpcore.transport import HttpTransport, LocalTransport, TransportError


# --------------------------------------------------------------------------- #
#  Startup banner                                                              #
# --------------------------------------------------------------------------- #
_LOGO = r"""

                          _
 _ __ ___   ___ _ __   __| |_  __
| '_ ` _ \ / __| '_ \ / _` \ \/ /
| | | | | | (__| |_) | (_| |>  <
|_| |_| |_|\___| .__/ \__,_/_/\_\
               |_|
"""


def render_banner(color: bool = True, subtitle: str = "") -> str:
    cyan = "\033[96m" if color else ""
    grey = "\033[90m" if color else ""
    bold = "\033[1m" if color else ""
    red = "\033[91m" if color else ""
    reset = "\033[0m" if color else ""

    out = [
        cyan + _LOGO + reset,
        f"  {bold}mcpdx{reset} {grey}v{__version__}{reset}  ·  "
        f"{bold}MCP Doctor{reset}  —  a security checkup for MCP servers",
    ]
    if subtitle:
        out.append(f"  {grey}{subtitle}{reset}")
    out.append(f"  {red}⚠  authorized testing only — you are responsible for scope{reset}")
    out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
#  Argument parsing                                                            #
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcpdx",
        description="MCP server security assessment toolkit (authorized testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples")[1] if "Examples" in __doc__ else None,
    )
    p.add_argument("--version", action="version", version=f"mcpdx {__version__}")

    # ---- shared option groups (attached to each subcommand) ----
    transport = argparse.ArgumentParser(add_help=False)
    tg = transport.add_argument_group("transport (choose one)")
    tg.add_argument("--local", metavar="CMD",
                    help="spawn a local MCP server; full command line as one string")
    tg.add_argument("--http", metavar="URL",
                    help="connect to a Streamable HTTP MCP endpoint")
    tg.add_argument("-H", "--header", action="append", default=[], metavar="K:V",
                    help="extra HTTP header (repeatable); e.g. -H 'Authorization: Bearer …'")
    tg.add_argument("-e", "--env", action="append", default=[], metavar="K=V",
                    help="env var for the spawned local server (repeatable)")
    tg.add_argument("--cwd", metavar="DIR", help="working directory for the local server")
    tg.add_argument("--insecure", action="store_true",
                    help="disable TLS certificate verification (HTTP transport)")
    tg.add_argument("--timeout", type=float, default=30.0, metavar="SEC",
                    help="per-request timeout in seconds (default 30)")

    output = argparse.ArgumentParser(add_help=False)
    og = output.add_argument_group("output / verbosity")
    og.add_argument("-v", "--verbose", action="count", default=0,
                    help="-v debug, -vv trace (raw JSON-RPC frames)")
    og.add_argument("-q", "--quiet", action="store_true", help="suppress log chatter")
    og.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    og.add_argument("--no-banner", action="store_true", help="do not print the logo")
    og.add_argument("--json", metavar="FILE", help="write a JSON report to FILE")
    og.add_argument("--md", metavar="FILE", help="write a Markdown report to FILE")
    og.add_argument("--sarif", metavar="FILE",
                    help="write a SARIF 2.1.0 report to FILE (for GitHub Code Scanning)")
    og.add_argument("--name", metavar="NAME",
                    help="save this scan to the local store under NAME so "
                         "`mcpdx report NAME` can re-render it later (audit/scan/fuzz)")

    drift = argparse.ArgumentParser(add_help=False)
    dg = drift.add_argument_group("drift / rug-pull detection")
    dg.add_argument("--baseline", metavar="FILE",
                    help="compare the current surface against a saved snapshot manifest "
                         "and report capability drift")
    dg.add_argument("--watch", type=int, default=0, metavar="N",
                    help="re-enumerate N extra times in-session and report any drift "
                         "(catches mid-session / post-usage capability swaps)")
    dg.add_argument("--watch-interval", type=float, default=2.0, metavar="SEC",
                    help="seconds between --watch re-enumerations (default 2)")

    sub = p.add_subparsers(dest="command", metavar="<command>")

    sp = sub.add_parser("enum", parents=[transport, output],
                        help="connect and enumerate tools/resources/prompts")
    sp.set_defaults(func=cmd_enum)

    sp = sub.add_parser("snapshot", parents=[transport, output],
                        help="capture a manifest of the declared surface for later drift comparison")
    sp.add_argument("--out", default="mcpdx-manifest.json", metavar="FILE",
                    help="manifest output path (default mcpdx-manifest.json)")
    sp.set_defaults(func=cmd_snapshot)

    sp = sub.add_parser("audit", parents=[transport, output, drift],
                        help="enumerate + run the passive (static) security audit")
    sp.set_defaults(func=cmd_audit)

    sp = sub.add_parser("scan", parents=[transport, output, drift],
                        help="full assessment: enum + static audit + optional active fuzz")
    sp.add_argument("--active", action="store_true",
                    help="ALSO run active fuzzing (invokes tools — see authorization note)")
    sp.add_argument("--yes", action="store_true",
                    help="skip the active-testing authorization prompt")
    sp.add_argument("--max-payloads", type=int, default=None,
                    help="cap payloads per family per parameter")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("fuzz", parents=[transport, output],
                        help="ACTIVE fuzzing of tool inputs (invokes tools)")
    sp.add_argument("--yes", action="store_true",
                    help="skip the active-testing authorization prompt")
    sp.add_argument("--max-payloads", type=int, default=None,
                    help="cap payloads per family per parameter")
    sp.add_argument("--no-robustness", action="store_true",
                    help="skip oversized/type-confusion robustness probes")
    sp.set_defaults(func=cmd_fuzz)

    sp = sub.add_parser("call", parents=[transport, output],
                        help="invoke a single tool / read a resource / get a prompt")
    sp.add_argument("--tool", help="tool name to call")
    sp.add_argument("--resource", help="resource URI to read")
    sp.add_argument("--prompt", help="prompt name to get")
    sp.add_argument("--args", default="{}",
                    help="JSON object of arguments (default {})")
    sp.set_defaults(func=cmd_call)

    # Offline: re-render a saved JSON report into other formats. No connection
    # is made — SARIF is consumed offline (CI upload), so it is decoupled from
    # the live scan and can be produced from a stored report.
    sp = sub.add_parser("report", parents=[output],
                        help="re-render a saved scan to SARIF/Markdown offline (no connection)")
    sp.add_argument("input", nargs="?", metavar="NAME|REPORT.json",
                    help="a scan saved with --name, or a JSON report path written with --json")
    sp.add_argument("--list", action="store_true",
                    help="list saved named scans and exit")
    sp.set_defaults(func=cmd_report)

    return p


# --------------------------------------------------------------------------- #
#  Setup helpers                                                               #
# --------------------------------------------------------------------------- #
def make_logger(args) -> Logger:
    verbosity = Logger.QUIET if args.quiet else args.verbose
    color = not args.no_color and sys.stdout.isatty()
    if args.no_color:
        color = False
    return Logger(verbosity=verbosity, color=color)


def build_transport(args, log):
    if bool(args.local) == bool(args.http):
        raise SystemExit("error: choose exactly one transport: --local CMD or --http URL")

    if args.local:
        env = None
        if args.env:
            env = dict(os.environ)
            for kv in args.env:
                if "=" not in kv:
                    raise SystemExit(f"error: --env expects K=V, got {kv!r}")
                k, v = kv.split("=", 1)
                env[k] = v
        return LocalTransport(args.local, log, env=env, cwd=args.cwd), {
            "transport": "local", "target": args.local,
        }

    headers = {}
    for h in args.header:
        if ":" not in h:
            raise SystemExit(f"error: --header expects 'Key: Value', got {h!r}")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    tls = args.http.lower().startswith("https")
    auth_supplied = any(k.lower() in ("authorization", "x-api-key", "api-key",
                                      "apikey", "cookie", "x-auth-token") for k in headers)
    return HttpTransport(args.http, log, headers=headers, insecure=args.insecure,
                         timeout=args.timeout), {
        "transport": "http", "target": args.http, "tls": tls,
        "url": args.http, "headers": headers, "auth_supplied": auth_supplied,
    }


def enumerate_surface(client, log):
    surface = {
        "tools": client.list_tools(),
        "resources": client.list_resources(),
        "resourceTemplates": client.list_resource_templates(),
        "prompts": client.list_prompts(),
    }
    log.ok(f"surface: {len(surface['tools'])} tools, "
           f"{len(surface['resources'])} resources, "
           f"{len(surface['resourceTemplates'])} templates, "
           f"{len(surface['prompts'])} prompts")
    return surface


def connect_and_enumerate(args, log):
    transport, meta = build_transport(args, log)
    transport.start()
    client = MCPClient(transport, log, timeout=args.timeout)
    log.info("performing initialize handshake")
    client.initialize()
    si = client.server_info
    log.ok(f"connected to {si.get('name','?')} v{si.get('version','?')} "
           f"(protocol {client.protocol_version})")
    if client.instructions:
        log.debug(f"server instructions: {client.instructions[:200]}")

    log.info("enumerating attack surface")
    surface = enumerate_surface(client, log)

    session = {
        **meta,
        "server_info": si,
        "capabilities": client.capabilities,
        "protocol_version": client.protocol_version,
        "instructions": client.instructions,
    }
    return client, transport, surface, session


def print_surface(surface, log):
    def section(title, items, fmt):
        log.out(log.c(f"\n  {title} ({len(items)})", "\033[1m", "\033[96m"))
        if not items:
            log.out("    (none)")
        for it in items:
            log.out("    " + fmt(it))

    section("TOOLS", surface["tools"],
            lambda t: f"• {t.get('name'):<28} {(_short(t.get('description')))}")
    section("RESOURCES", surface["resources"],
            lambda r: f"• {r.get('uri'):<40} {(_short(r.get('description')))}")
    section("RESOURCE TEMPLATES", surface["resourceTemplates"],
            lambda r: f"• {r.get('uriTemplate'):<40} {(_short(r.get('description')))}")
    section("PROMPTS", surface["prompts"],
            lambda p: f"• {p.get('name'):<28} {(_short(p.get('description')))}")
    log.out("")


def _short(text, n=60):
    if not text:
        return ""
    text = " ".join(str(text).split())
    return text[:n] + ("…" if len(text) > n else "")


# --------------------------------------------------------------------------- #
#  Named-scan store                                                            #
# --------------------------------------------------------------------------- #
# Scans named with `--name` are saved here (relative to the working directory)
# so `mcpdx report <name>` can find them later without juggling file paths.
SCAN_STORE = os.path.join(".mcpdx", "scans")


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.") or "scan"


def _store_path(name: str) -> str:
    return os.path.join(SCAN_STORE, _safe_name(name) + ".json")


def _resolve_report_ref(ref: str):
    """Resolve a `report` argument to a file path: an explicit path wins,
    otherwise treat it as the name of a stored scan."""
    if os.path.isfile(ref):
        return ref
    stored = _store_path(ref)
    return stored if os.path.isfile(stored) else None


def _list_scans(log) -> int:
    if not os.path.isdir(SCAN_STORE):
        log.out(f"  no saved scans (store: {SCAN_STORE}/)")
        return 0
    names = sorted(fn[:-5] for fn in os.listdir(SCAN_STORE) if fn.endswith(".json"))
    if not names:
        log.out(f"  no saved scans (store: {SCAN_STORE}/)")
        return 0
    log.out("")
    log.out(log.c(f"  saved scans ({SCAN_STORE}/)", "\033[1m"))
    for name in names:
        try:
            with open(_store_path(name), "r", encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError):
            log.out(f"    {name:<22} (unreadable)")
            continue
        meta = doc.get("meta", {}) or {}
        summ = doc.get("summary", {}) or {}
        counts = " ".join(f"{s[0]}:{summ.get(s, 0)}"
                          for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
        log.out(f"    {name:<22} {meta.get('captured_at', '?'):<22} {counts}")
        log.out(f"    {'':<22} target: {_short(meta.get('target', '?'), 56)}")
    log.out("")
    return 0


def emit_reports(args, session, surface, findings, log):
    meta = {
        "target": session.get("target"),
        "transport": session.get("transport"),
        "server": f"{session.get('server_info',{}).get('name','?')} "
                  f"{session.get('server_info',{}).get('version','')}".strip(),
        "protocol": session.get("protocol_version"),
        "tools": len(surface.get("tools", [])),
        "captured_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    # console
    log.out("")
    log.out(log.c("  ── FINDINGS ─────────────────────────────────────────────", "\033[1m"))
    log.out("")
    log.out(R.render_console(findings, color=log.color))
    log.out(R.render_summary(findings, color=log.color))
    log.out("")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(R.render_json(meta, surface, findings))
        log.ok(f"JSON report written: {args.json}")
    if args.md:
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(R.render_markdown(meta, surface, findings))
        log.ok(f"Markdown report written: {args.md}")
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as f:
            f.write(sarif.render_sarif(meta, surface, findings))
        log.ok(f"SARIF report written: {args.sarif}")
    if getattr(args, "name", None):
        path = _store_path(args.name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(R.render_json(meta, surface, findings))
        log.ok(f"saved scan '{_safe_name(args.name)}' "
               f"(reference it with: mcpdx report {_safe_name(args.name)})")


def confirm_active(args, log) -> bool:
    if getattr(args, "yes", False):
        return True
    log.out("")
    log.out(log.c("  ⚠  ACTIVE TESTING WARNING", "\033[1m", "\033[91m"))
    log.out("  Active fuzzing will INVOKE the target's tools with attack payloads.")
    log.out("  This may create/modify/delete data, make outbound requests, or run")
    log.out("  commands on the target. Only proceed on systems you are authorized to test.")
    try:
        ans = input("  Type 'yes' to confirm you have authorization: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return ans == "yes"


# --------------------------------------------------------------------------- #
#  Commands                                                                    #
# --------------------------------------------------------------------------- #
def cmd_enum(args, log):
    client, transport, surface, session = connect_and_enumerate(args, log)
    try:
        print_surface(surface, log)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump({"session": _json_safe(session), "surface": surface}, f, indent=2)
            log.ok(f"JSON written: {args.json}")
    finally:
        transport.close()
    return 0


def run_probes(session, args, log):
    """Read-only access-control / session / TLS probes (HTTP only)."""
    if session.get("transport") != "http":
        log.debug("auth/session/TLS probes skipped (local transport)")
        return []
    findings = []
    findings += AuthSessionProbe(log, session["url"], session.get("headers", {}),
                                 insecure=args.insecure, timeout=args.timeout).run()
    findings += TlsProbe(log, session["url"], insecure=args.insecure,
                         timeout=args.timeout).run()
    return findings


def run_active_netprobes(session, args, log):
    """Active load-generating probes (HTTP only); run in the active phase."""
    if session.get("transport") != "http":
        return []
    return RateLimitProbe(log, session["url"], session.get("headers", {}),
                          insecure=args.insecure, timeout=args.timeout).run()


def run_drift(args, client, surface, session, log):
    """Baseline comparison + in-session watch for capability drift / rug pulls."""
    findings = []
    detector = DriftDetector(log)

    baseline_path = getattr(args, "baseline", None)
    if baseline_path:
        try:
            with open(baseline_path, encoding="utf-8") as f:
                manifest = json.load(f)
        except OSError as e:
            log.error(f"cannot read baseline manifest: {e}")
        except json.JSONDecodeError as e:
            log.error(f"baseline manifest is not valid JSON: {e}")
        else:
            log.info(f"comparing surface against baseline {baseline_path}")
            findings += detector.compare_manifest(manifest, surface, label="baseline")

    n = getattr(args, "watch", 0) or 0
    if n:
        interval = getattr(args, "watch_interval", 2.0)
        log.info(f"watching for drift: {n} re-enumeration(s) every {interval}s")
        for i in range(n):
            time.sleep(interval)
            log.info(f"watch re-enumeration {i + 1}/{n}")
            try:
                current = enumerate_surface(client, log)
            except (TransportError, RpcError) as e:
                log.warn(f"watch re-enumeration failed: {e}")
                break
            findings += detector.compare_surface(surface, current, label=f"watch#{i + 1}")

    if findings:
        log.ok(f"drift detection: {len(findings)} change finding(s)")
    return findings


def cmd_snapshot(args, log):
    client, transport, surface, session = connect_and_enumerate(args, log)
    try:
        print_surface(surface, log)
        captured = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
        manifest = drift_mod.build_manifest(surface, session, captured_at=captured)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        log.ok(f"snapshot written: {args.out} ({len(manifest['items'])} item(s))")
        log.info(f"compare later with: mcpdx audit <transport> --baseline {args.out}")
    finally:
        transport.close()
    return 0


def cmd_audit(args, log):
    client, transport, surface, session = connect_and_enumerate(args, log)
    try:
        print_surface(surface, log)
        findings = Auditor(log).run(surface, session)
        findings = findings + run_probes(session, args, log)
        findings = findings + run_drift(args, client, surface, session, log)
        emit_reports(args, session, surface, findings, log)
    finally:
        transport.close()
    return _exit_code(findings)


def cmd_scan(args, log):
    client, transport, surface, session = connect_and_enumerate(args, log)
    try:
        print_surface(surface, log)
        findings = Auditor(log).run(surface, session)
        findings = findings + run_probes(session, args, log)
        if args.active:
            if confirm_active(args, log):
                fz = Fuzzer(client, log, max_payloads=args.max_payloads)
                findings = findings + fz.run(surface)
                findings = findings + run_active_netprobes(session, args, log)
                # Post-usage drift: tools were invoked; re-enumerate and diff
                # against the pre-fuzz surface to catch swaps-after-use.
                log.info("re-enumerating after tool invocation (post-usage drift check)")
                try:
                    post = enumerate_surface(client, log)
                    findings += DriftDetector(log).compare_surface(
                        surface, post, label="post-invocation")
                except (TransportError, RpcError) as e:
                    log.warn(f"post-usage re-enumeration failed: {e}")
            else:
                log.warn("active testing not confirmed — skipping fuzz phase")
        else:
            log.info("static audit only (pass --active to also fuzz tool inputs)")
        findings = findings + run_drift(args, client, surface, session, log)
        emit_reports(args, session, surface, findings, log)
    finally:
        transport.close()
    return _exit_code(findings)


def cmd_fuzz(args, log):
    client, transport, surface, session = connect_and_enumerate(args, log)
    try:
        if not confirm_active(args, log):
            log.error("active testing not confirmed — aborting")
            return 2
        fz = Fuzzer(client, log, max_payloads=args.max_payloads,
                    include_robustness=not args.no_robustness)
        findings = fz.run(surface)
        findings = findings + run_active_netprobes(session, args, log)
        emit_reports(args, session, surface, findings, log)
    finally:
        transport.close()
    return _exit_code(findings)


def cmd_call(args, log):
    client, transport, surface, session = connect_and_enumerate(args, log)
    try:
        try:
            call_args = json.loads(args.args)
        except json.JSONDecodeError as e:
            raise SystemExit(f"error: --args is not valid JSON: {e}")

        if args.tool:
            result = client.call_tool(args.tool, call_args)
        elif args.resource:
            result = client.read_resource(args.resource)
        elif args.prompt:
            result = client.get_prompt(args.prompt, call_args)
        else:
            raise SystemExit("error: specify one of --tool / --resource / --prompt")

        log.out("")
        log.out(json.dumps(result, indent=2, ensure_ascii=False))
        log.out("")
    finally:
        transport.close()
    return 0


_FINDING_FIELDS = ("id", "title", "severity", "category", "target",
                   "evidence", "recommendation", "metadata")


def cmd_report(args, log):
    """Offline: re-render a saved scan into SARIF / Markdown / console.

    Makes no network connection — useful for producing SARIF in a CI step that
    has the stored report but no access to the original target. The argument is
    a scan name (saved with --name) or a JSON report path.
    """
    if args.list:
        return _list_scans(log)
    if not args.input:
        raise SystemExit("error: give a saved scan NAME or a JSON report path "
                         "(or `mcpdx report --list` to see saved scans)")

    path = _resolve_report_ref(args.input)
    if path is None:
        raise SystemExit(f"error: {args.input!r} is not a file and no saved scan "
                         "has that name (try `mcpdx report --list`)")
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except OSError as e:
        raise SystemExit(f"error: cannot read report {path!r}: {e}")
    except json.JSONDecodeError as e:
        raise SystemExit(f"error: {path!r} is not valid JSON: {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise SystemExit(f"error: {path!r} is not an mcpdx JSON report "
                         "(expected a 'findings' array; write one with --json or --name)")

    meta = doc.get("meta", {}) or {}
    surface = doc.get("surface", {}) or {}
    findings = []
    for d in doc["findings"]:
        if isinstance(d, dict):
            findings.append(R.Finding(**{k: d[k] for k in _FINDING_FIELDS if k in d}))
    log.ok(f"loaded {len(findings)} finding(s) from {path}")

    wrote = False
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(R.render_json(meta, surface, findings))
        log.ok(f"JSON report written: {args.json}")
        wrote = True
    if args.md:
        with open(args.md, "w", encoding="utf-8") as f:
            f.write(R.render_markdown(meta, surface, findings))
        log.ok(f"Markdown report written: {args.md}")
        wrote = True
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as f:
            f.write(sarif.render_sarif(meta, surface, findings))
        log.ok(f"SARIF report written: {args.sarif}")
        wrote = True
    if not wrote:
        # No output target: re-render the saved findings to the console.
        log.out("")
        log.out(R.render_console(findings, color=log.color))
        log.out(R.render_summary(findings, color=log.color))
        log.out("")
    return _exit_code(findings)


# --------------------------------------------------------------------------- #
#  Misc                                                                        #
# --------------------------------------------------------------------------- #
def _exit_code(findings) -> int:
    """Exit non-zero when notable findings exist (CI-friendly)."""
    for f in findings:
        if f.severity in ("CRITICAL", "HIGH"):
            return 3
    for f in findings:
        if f.severity == "MEDIUM":
            return 1
    return 0


def _json_safe(obj):
    try:
        json.dumps(obj)
        return obj
    except TypeError:
        return str(obj)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    log = make_logger(args)
    if not args.no_banner and not args.quiet:
        target = (getattr(args, "local", None) or getattr(args, "http", None)
                  or getattr(args, "input", None) or "?")
        log.out(render_banner(color=log.color, subtitle=f"target: {target}"))

    try:
        return args.func(args, log)
    except KeyboardInterrupt:
        log.error("interrupted")
        return 130
    except TransportError as e:
        log.error(f"transport error: {e}")
        return 4
    except RpcError as e:
        log.error(f"protocol error: {e}")
        return 4
    except SystemExit:
        raise
    except Exception as e:  # last-resort guard so the tool fails cleanly
        log.error(f"unexpected error: {e}")
        if log.verbosity >= Logger.VERBOSE:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
