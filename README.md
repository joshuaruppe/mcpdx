<div align="center">
<pre>
                          _
 _ __ ___   ___ _ __   __| |_  __
| '_ ` _ \ / __| '_ \ / _` \ \/ /
| | | | | | (__| |_) | (_| |&gt;  &lt;
|_| |_| |_|\___| .__/ \__,_/_/\_\
               |_|
</pre>

# mcpdx · MCP Doctor

**A security checkup for MCP servers**

![Python](https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![MCP](https://img.shields.io/badge/MCP-2025--11--25-8A2BE2)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)
![Use](https://img.shields.io/badge/use-authorized_testing_only-red)

</div>

`mcpdx` is a zero-dependency toolkit for **authorized** security assessment of
[Model Context Protocol](https://modelcontextprotocol.io) servers. It connects
over **stdio** or **Streamable HTTP**, enumerates the exposed attack surface
(tools, resources, prompts), runs a **passive static audit**, and, only when you
explicitly opt in, **actively fuzzes** tool inputs. Findings render to the
console or export as JSON, Markdown, or SARIF, with CI-friendly exit codes.

> [!CAUTION]
> This tool can invoke a target server's tools with attack payloads, which may
> create/modify/delete data, make outbound requests, or execute commands on the
> target. **Only use it against systems you own or are explicitly authorized to
> test.** You are responsible for staying in scope. Active phases are gated
> behind an explicit `--active` flag and an interactive authorization prompt.

## Contents

- [mcpdx · MCP Doctor](#mcpdx--mcp-doctor)
  - [Contents](#contents)
  - [Features](#features)
  - [Install](#install)
  - [Quick start](#quick-start)
  - [Commands](#commands)
  - [Launch options](#launch-options)
  - [Examples](#examples)
  - [What it checks](#what-it-checks)
    - [Passive (static, no tool is invoked)](#passive-static-no-tool-is-invoked)
    - [Active (only with `--active` / `fuzz`, invokes tools)](#active-only-with---active--fuzz-invokes-tools)
    - [Access-control \& session probes (HTTP, read-only, run automatically by `audit`/`scan`)](#access-control--session-probes-http-read-only-run-automatically-by-auditscan)
    - [Capability drift / rug-pull detection (`audit`/`scan`, read-only)](#capability-drift--rug-pull-detection-auditscan-read-only)
  - [Exit codes](#exit-codes)
  - [Project layout](#project-layout)
  - [License](#license)

## Features

- 🔍 **Enumerate** the full declared surface (tools, resources, resource
  templates, and prompts) over stdio or Streamable HTTP.
- 🛡️ **Passive static audit**: tool/prompt poisoning, hidden Unicode, tool-name
  collision, sensitive-capability and input-validation gaps, risky `icons[]`
  sources, and known-CVE flagging. No tool is ever invoked.
- 💥 **Active fuzzing** *(opt-in)*: path traversal, command/SQL/template
  injection, SSRF, NoSQL and prototype pollution, plus live output-poisoning and
  secret-leak scanning of tool responses.
- 🔄 **Drift / rug-pull detection**: snapshot the surface and diff later, or
  re-enumerate in-session to catch post-usage definition swaps.
- 🌐 **Transport and access-control probes** (HTTP): auth-boundary delta, forged
  session acceptance, TLS posture / downgrade, and rate-limiting.
- 📄 **Reports**: colorized console, plus JSON, Markdown, and SARIF 2.1.0
  (GitHub Code Scanning) export.
- 🧰 **Zero dependencies**: Python 3.8+ standard library only. Drop it on an
  engagement box and run.

## Install

```bash
git clone <repo> mcpdx && cd mcpdx
python mcpdx.py --help        # nothing to install; stdlib only
```

## Quick start

```bash
# Passive audit (read-only) of a local stdio server
python mcpdx.py audit --stdio "python my_server.py"

# Full assessment incl. ACTIVE fuzzing, with JSON + Markdown reports
python mcpdx.py scan --stdio "python my_server.py" --active --json out.json --md out.md

# Try it against the bundled vulnerable fixture
python mcpdx.py scan --stdio "python examples/vulnerable_server.py" --active --yes
```

## Commands

| Command | What it does | Touches the target? |
|---------|--------------|---------------------|
| `enum`  | Connect + list tools, resources, templates, prompts | read-only handshake |
| `snapshot` | Capture a manifest of the declared surface for later drift comparison | read-only |
| `audit` | `enum` + **passive** static security audit (+ drift, HTTP probes) | read-only |
| `scan`  | `audit` + **optional** active fuzz (`--active`) | read-only, or active w/ flag |
| `fuzz`  | **Active** fuzzing of tool inputs only | **yes, invokes tools** |
| `call`  | Manually invoke one tool / read a resource / get a prompt | yes (one call) |
| `report` | Re-render a saved scan (by `--name` or path) to SARIF / Markdown **offline**; `--list` to list saved scans | no (reads a file) |

## Launch options

<details>
<summary><b>Transport</b> (choose exactly one)</summary>

| Flag | Meaning |
|------|---------|
| `--stdio "CMD …"` | Spawn a local MCP server; pass the full command line as one string |
| `--http URL` | Connect to a Streamable HTTP MCP endpoint |
| `-H, --header "K: V"` | Add an HTTP header (repeatable), e.g. `-H "Authorization: Bearer …"` |
| `-e, --env "K=V"` | Set an env var for the spawned stdio server (repeatable) |
| `--cwd DIR` | Working directory for the stdio server |
| `--insecure` | Disable TLS certificate verification (HTTP) |
| `--timeout SEC` | Per-request timeout (default 30) |

</details>

<details>
<summary><b>Output / verbosity</b></summary>

| Flag | Meaning |
|------|---------|
| `-v` | Debug logging (protocol-level chatter) |
| `-vv` | **Trace**: dumps raw JSON-RPC frames in both directions |
| `-q, --quiet` | Suppress log chatter (results still print) |
| `--no-color` | Disable ANSI colour |
| `--no-banner` | Don't print the ASCII logo |
| `--json FILE` | Write a machine-readable JSON report |
| `--md FILE` | Write a Markdown report |
| `--sarif FILE` | Write a SARIF 2.1.0 report (for GitHub Code Scanning) |
| `--name NAME` | Save the scan to the local store (`.mcpdx/scans/`) so `report NAME` can re-render it later |

</details>

<details>
<summary><b>Active-testing flags</b> (`scan` / `fuzz`)</summary>

| Flag | Meaning |
|------|---------|
| `--active` | (`scan`) also run the active fuzz phase |
| `--yes` | Skip the interactive authorization prompt (for automation/CI) |
| `--max-payloads N` | Cap payloads per family, per parameter |
| `--no-robustness` | (`fuzz`) skip oversized / type-confusion probes |

</details>

<details>
<summary><b>Drift / rug-pull flags</b> (`audit` / `scan`)</summary>

| Flag | Meaning |
|------|---------|
| `--baseline FILE` | Compare the current surface against a saved `snapshot` manifest and report capability drift |
| `--watch N` | Re-enumerate N extra times in-session and report drift (catches mid-session / post-usage swaps) |
| `--watch-interval SEC` | Seconds between `--watch` re-enumerations (default 2) |
| `--out FILE` | (`snapshot`) manifest output path (default `mcpdx-manifest.json`) |

</details>

## Examples

```bash
# Enumerate a local stdio server
python mcpdx.py enum --stdio "npx -y @modelcontextprotocol/server-filesystem ./data"

# Passive audit of a remote HTTP server, verbose, export Markdown
python mcpdx.py audit --http https://mcp.example.com/mcp -v --md report.md \
    -H "Authorization: Bearer $TOKEN"

# Full assessment including ACTIVE fuzzing, JSON + Markdown reports
python mcpdx.py scan --stdio "python my_server.py" --active --json out.json --md out.md

# Audit and emit SARIF for upload to GitHub Code Scanning
python mcpdx.py audit --stdio "python my_server.py" --sarif mcpdx.sarif

# Name a scan, then re-render it later by name (offline, no re-scan)
python mcpdx.py scan --stdio "python my_server.py" --name prod-api
python mcpdx.py report prod-api --sarif mcpdx.sarif --md report.md
python mcpdx.py report --list            # show saved scans

# (a saved JSON report path works too, in place of a name)
python mcpdx.py report report.json --sarif mcpdx.sarif

# Trace every JSON-RPC frame
python mcpdx.py audit --stdio "python my_server.py" -vv

# Manually invoke a single tool
python mcpdx.py call --stdio "python my_server.py" \
    --tool read_file --args '{"path":"README.md"}'

# Snapshot now, then diff on a retest to catch capability drift / rug pulls
python mcpdx.py snapshot --stdio "python my_server.py" --out baseline.json
python mcpdx.py audit --stdio "python my_server.py" --baseline baseline.json

# Watch a server for a post-usage definition swap
python mcpdx.py audit --stdio "python my_server.py" --watch 3 --watch-interval 5
```

A deliberately-vulnerable demo server lives in [`examples/`](examples/) so you
can see findings without pointing the tool at anything real:

```bash
# stdio fixture: poisoning, collision, command injection, output poisoning, …
python mcpdx.py scan --stdio "python examples/vulnerable_server.py" --active --yes

# HTTP fixture: CVE flag, auth-boundary, forged-session findings
python examples/insecure_http_server.py 8765 &
python mcpdx.py audit --http http://127.0.0.1:8765/mcp -H "Authorization: Bearer x"
```

> [!WARNING]
> The files in `examples/` are **test fixtures only**. Never deploy them.

## What it checks

### Passive (static, no tool is invoked)

- Tool/prompt **poisoning**: injection-style phrasing in advertised text. Beyond
  the top-level description, it scans the tool **`title`** and every **parameter
  `description`** (recursively, including nested schemas), a common place to hide
  instructions a reviewer skims past, plus forged chat-template / role delimiters
  (`<|im_start|>`, `<<SYS>>`, `### system`, …).
- **Hidden/invisible Unicode** (zero-width, RTL override, Unicode tag block) used
  to smuggle instructions past a human reviewer.
- **Tool-name collision / shadowing**: duplicate or look-alike tool identifiers
  (invocation-path confusion / namespace squatting).
- **Markdown links / URLs** and **approval-coercion phrasing** ("always approve",
  "do not ask") in advertised descriptions.
- **Sensitive capability** exposure (code execution, filesystem, network,
  database, secrets, messaging) inferred from names/descriptions.
- **Input-validation** gaps: unconstrained free-text params feeding sensitive sinks.
- **Destructive** tools (via `annotations.destructiveHint`).
- **Templated resources** that look prone to path traversal.
- **Transport** weaknesses: plaintext HTTP, enumeration without authentication.
- **Risky icon sources**: `icons[]` metadata (MCP 2025-11-25) carrying SVG
  `data:`/`file:` URIs (script-bearing) or off-origin `http(s)` sources (an
  exfiltration/tracking beacon when a client UI renders them).
- **Known-CVE / vulnerable-version** flagging from `serverInfo` (e.g. MCP-Inspector
  < 0.14.1, CVE-2025-49596).
- Server identity / capability recon.

### Active (only with `--active` / `fuzz`, invokes tools)

- **Path traversal** (`../../etc/passwd`, `etc/shadow`, encoded, SMB/UNC, `file://`).
- **Command injection** (shell metacharacters with a benign arithmetic/echo canary).
- **SQL injection** (error-based) and **SSTI** (`{{7*7}}`/`${7*7}` evaluating to `49`).
- **SSRF** (cloud metadata, loopback, `file://`, custom URI schemes).
- **NoSQL / prototype pollution**: operator objects (`{"$ne":null}`, `__proto__`)
  into object-typed params (best-effort, error-based; confirm manually).
- **Output poisoning**: scans live tool *outputs* for injected instructions and
  hidden Unicode (treat every output as untrusted input to the next agent).
- **Secret exposure**: leaked credentials in tool output, including **AI-provider
  keys** (Anthropic `sk-ant-`, OpenAI project/legacy), AWS/GCP/Slack/GitHub
  (classic + fine-grained), GitLab, HuggingFace, npm, and Telegram tokens, JWTs,
  and private keys.
- **Output-schema mismatch**: declared `outputSchema` vs. actually-returned fields.
- **Robustness / info disclosure** (oversized input, type confusion that leaks
  stack traces and internal paths).

> [!NOTE]
> A reflection guard strips the echoed payload from responses before matching, so
> tools that merely echo input don't generate false positives.

### Access-control & session probes (HTTP, read-only, run automatically by `audit`/`scan`)

- **Auth-boundary delta**: if credentials are supplied, re-tests enumeration with
  them stripped, flagging servers that remain enumerable without authentication.
- **Session validation**: sends a never-issued `Mcp-Session-Id` with no handshake,
  flagging servers that honour forged/unbound sessions.
- **TLS posture**: inspects the negotiated TLS version/cipher (flags 1.0/1.1 and
  weak ciphers) and tests for a plaintext-`http://` downgrade of an `https` endpoint.
- **Rate limiting** (active phase): a short concurrent burst flags servers with no
  throttling on session/tool creation (prompt-storm / resource-exhaustion exposure).

### Capability drift / rug-pull detection (`audit`/`scan`, read-only)

- **`snapshot` + `--baseline`**: hashes every tool/prompt/resource definition into
  a manifest; a later run diffs against it and flags added / removed / changed
  capabilities. Changed text is re-run through the poisoning + hidden-Unicode
  scanners, so a description that *mutates into* an injection payload is HIGH.
- **`--watch N`**: re-enumerates in-session to catch a server that swaps benign
  definitions for malicious ones after a few uses (the documented WhatsApp pattern).
- **post-usage check**: `scan --active` automatically re-enumerates after fuzzing
  and diffs against the pre-fuzz surface.

> [!NOTE]
> Drift detection finds drift you actually *observe*. It can't prove the absence
> of a rug pull that only triggers for a different identity, environment, or
> real-world condition you don't reproduce, so report it as such.

These map to the concerns in NSA CSI *"Model Context Protocol (MCP): Security
Design Considerations for AI-Driven Automation"* (U/OO/6030316-26, May 2026):
access control, tool poisoning, parameter injection/ACE, output poisoning,
tool-name collision, token/session security, transport security, capability
drift / rug pulls, and known-vulnerability tracking.

## Exit codes

`mcpdx` is CI-friendly. The process exit code reflects the worst finding:

| Code | Meaning |
|:----:|---------|
| `0` | Clean, no findings |
| `1` | Medium findings |
| `3` | High / critical findings |
| `2` | Authorization declined |
| `4` | Connection / protocol error |

## Project layout

```
mcpdx/
├── mcpdx.py                      CLI entry point (launch options, subcommands, banner)
├── requirements.txt              (empty) zero runtime deps; stdlib only
├── mcpcore/
│   ├── log.py                    verbosity-aware colour logger (-v / -vv)
│   ├── transport.py              stdio + Streamable HTTP JSON-RPC transports
│   ├── client.py                 MCP client (handshake, enumeration, invocation)
│   ├── payloads.py               detection signatures + active payloads
│   ├── audit.py                  passive static auditor (poisoning, collision, CVE, …)
│   ├── fuzz.py                   active fuzzer (+ live output-poisoning scan)
│   ├── probes.py                 HTTP auth-boundary + session-validation probes
│   ├── netprobe.py               TLS posture / downgrade + rate-limit probes
│   ├── drift.py                  capability-drift / rug-pull detection
│   ├── report.py                 Finding model + console / JSON / Markdown renderers
│   └── sarif.py                  SARIF 2.1.0 renderer (offline; GitHub Code Scanning)
└── examples/
    ├── vulnerable_server.py      stdio test fixture
    └── insecure_http_server.py   HTTP test fixture (CVE / auth / session)
```

## License

No license has been chosen yet. Until a `LICENSE` file is added, default
copyright applies (all rights reserved). If you intend this to be open source,
add one. MIT is a common, permissive choice for tooling like this.
