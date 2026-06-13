"""Detection signatures and active-test payloads.

Signatures drive the *static* audit (pattern matching against the declared
attack surface). Payloads drive the *active* fuzzer (only used with explicit
authorization). Keep payloads benign-by-default: they probe for a vulnerable
code path without causing damage.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------- #
#  Static signatures                                                           #
# --------------------------------------------------------------------------- #

# Tool/resource names hinting at a sensitive capability, grouped by class.
SENSITIVE_CAPABILITIES = {
    "code_execution": [
        "exec", "eval", "shell", "command", "cmd", "run", "spawn", "subprocess",
        "bash", "powershell", "python", "script", "system", "os_",
    ],
    "filesystem": [
        "read_file", "write_file", "readfile", "writefile", "delete", "unlink",
        "remove", "rm", "fs_", "file", "path", "directory", "mkdir", "rmdir",
        "list_dir", "move", "copy", "chmod",
    ],
    "network": [
        "fetch", "http", "request", "curl", "wget", "url", "proxy", "download",
        "upload", "webhook", "ssrf", "get_url", "open_url",
    ],
    "database": [
        "sql", "query", "db_", "database", "mongo", "redis", "execute_query",
        "select", "insert", "update_row", "drop",
    ],
    "secrets": [
        "secret", "token", "credential", "password", "apikey", "api_key",
        "private_key", "env", "config", "vault",
    ],
    "messaging": [
        "send_email", "send_mail", "sms", "slack", "discord", "post_message",
        "tweet", "publish",
    ],
}

# Phrases that, when embedded in a tool/prompt description, indicate an
# attempt to steer the *consuming LLM* (tool poisoning / prompt injection).
PROMPT_INJECTION_MARKERS = [
    "ignore previous", "ignore the above", "ignore all previous",
    "disregard", "do not tell", "don't tell the user", "do not mention",
    "without informing", "without telling", "secretly", "hidden instruction",
    "system prompt", "you are now", "new instructions", "as an ai",
    "before using this tool", "before you use", "important:", "<important>",
    "always include", "exfiltrate", "send to", "forward the", ".ssh",
    "id_rsa", "read the file", "do the following first", "act as",
    "override", "jailbreak", "developer mode",
    # approval-coercion phrasing (checklist §7)
    "always approve", "auto approve", "auto-approve", "automatically approve",
    "always allow", "do not ask", "don't ask", "no confirmation",
    "without confirmation", "skip confirmation", "approve this",
    # chat-template / role delimiters smuggled into metadata or output — a strong
    # tool-poisoning signal: they try to forge a turn boundary or system role.
    "<|im_start|>", "<|im_end|>", "<|system|>", "<|user|>", "<|assistant|>",
    "<|endoftext|>", "[/inst]", "<<sys>>", "<</sys>>",
    "### instruction", "### system", "<system>", "</system>",
    "<|eot_id|>", "<|start_header_id|>",
    # current indirect-injection / exfil phrasings
    "your real task", "your actual task", "the user has approved",
    "this is authorized", "reveal your system", "print your system prompt",
    "repeat the words above", "repeat everything above",
]

# Markdown links / images in advertised text can hide URLs or steer an LLM that
# renders them (checklist §7). Captures [text](url), ![alt](url), and bare URLs.
MARKDOWN_LINK = re.compile(
    r"!?\[[^\]]*\]\([^)]+\)|\bhttps?://[^\s)]+", re.I
)

# Invisible / formatting unicode often used to smuggle hidden instructions.
INVISIBLE_UNICODE = [
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "⁠",  # word joiner
    "﻿",  # BOM / zero width no-break space
    "­",  # soft hyphen
    "‮",  # right-to-left override
    "‭",  # left-to-right override
    "⁡", "⁢", "⁣",  # function application / invisible times/sep
]
# Unicode "tag" block (E0000-E007F) used for fully invisible payloads.
TAG_BLOCK = (0xE0000, 0xE007F)


def find_invisible(text: str):
    """Return a list of (codepoint_hex, name-ish) for hidden chars in text."""
    hits = []
    for ch in text:
        cp = ord(ch)
        if ch in INVISIBLE_UNICODE or (TAG_BLOCK[0] <= cp <= TAG_BLOCK[1]):
            hits.append(f"U+{cp:04X}")
    return hits


def match_capability(name: str, description: str = ""):
    """Return the set of capability classes a tool name/description hints at."""
    hay = f"{name} {description}".lower()
    classes = set()
    for klass, needles in SENSITIVE_CAPABILITIES.items():
        for n in needles:
            if n in hay:
                classes.add(klass)
                break
    return classes


def match_injection_markers(text: str):
    low = text.lower()
    return [m for m in PROMPT_INJECTION_MARKERS if m in low]


def analyze_icons(icons):
    """Inspect `icons[]` metadata (MCP 2025-11-25) for risky icon sources.

    The icons array lets a server attach a `src` URL (or data: URI) to a tool /
    resource / prompt that a client UI renders. That introduces a new untrusted
    fetch/render surface: SVGs can carry executable script, off-origin URLs act
    as a tracking/exfil beacon when rendered, and http:// sources are cleartext.

    Returns a list of (severity, reason, src) for each noteworthy icon source.
    """
    findings = []
    if not isinstance(icons, list):
        return findings
    for icon in icons:
        if not isinstance(icon, dict):
            continue
        src = (icon.get("src") or "").strip()
        if not src:
            continue
        low = src.lower()
        mime = (icon.get("mimeType") or "").lower()
        is_svg = "svg" in mime or low.startswith("data:image/svg") or ".svg" in low.split("?")[0]
        if low.startswith("data:"):
            if is_svg:
                findings.append(("HIGH",
                    "inline data: URI SVG icon — SVGs can embed executable script "
                    "(<script>/onload) that runs when a client renders the icon", src))
            else:
                findings.append(("LOW",
                    "inline data: URI icon — verify it decodes to a benign image", src))
        elif low.startswith("http://"):
            findings.append(("MEDIUM",
                "icon fetched over plaintext http:// — cleartext and an off-origin "
                "fetch/beacon when the client renders it", src))
        elif low.startswith("file:"):
            findings.append(("MEDIUM",
                "file:// icon source — points the rendering client at a local path", src))
        elif low.startswith("https://"):
            sev = "MEDIUM" if is_svg else "LOW"
            extra = " and is an SVG (can embed script)" if is_svg else ""
            findings.append((sev,
                "external https icon source — off-origin fetch when rendered "
                "(tracking/beacon vector); confirm the domain is trusted" + extra, src))
    return findings


# --------------------------------------------------------------------------- #
#  Active payloads (used only with --active / `fuzz`)                          #
# --------------------------------------------------------------------------- #

# Each payload carries the string to inject plus a detector that recognises a
# successful / interesting response. Detectors are intentionally conservative.

PATH_TRAVERSAL = [
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "../../../../../../etc/shadow",
    "file:///etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "\\\\mcpdx.invalid\\share\\probe",   # SMB/UNC path injection (Windows)
]
PATH_TRAVERSAL_INDICATORS = [
    re.compile(r"root:.*:0:0:"),            # /etc/passwd
    re.compile(r"root:[*!]?\$\d\$"),        # /etc/shadow hashed entry
    re.compile(r"\[(extensions|fonts|mci extensions)\]", re.I),  # win.ini
    re.compile(r"\[boot loader\]", re.I),
]

# SQL injection (checklist §5) — error-based detection.
SQL_INJECTION = [
    "' OR '1'='1'-- -",
    "\" OR \"1\"=\"1\"-- -",
    "1' OR '1'='1",
    "'; --",
    "') OR ('1'='1",
    "' UNION SELECT NULL-- -",
]
SQL_INJECTION_INDICATORS = [
    re.compile(r"(?i)you have an error in your sql syntax"),
    re.compile(r"(?i)warning:\s*\w*_?(mysql|pg|sqlite|mssql)"),
    re.compile(r"(?i)unclosed quotation mark after the character string"),
    re.compile(r"(?i)syntax error at or near"),
    re.compile(r"(?i)sqlite3?\.(operational|programming)?error"),
    re.compile(r"(?i)psycopg2?\.|pg::|org\.postgresql"),
    re.compile(r"(?i)ORA-\d{5}|SQLSTATE\[|SQLITE_ERROR"),
    re.compile(r"(?i)microsoft (sql server|ole db)|odbc sql"),
]

# Server-Side Template Injection (checklist §5) — arithmetic canary 7*7=49.
SSTI = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${{7*7}}", "{{7*'7'}}",
]
SSTI_INDICATORS = [
    re.compile(r"(?<!\d)49(?!\d)"),     # 7*7 evaluated
    re.compile(r"7777777"),              # 7*'7' string-multiplied
]

# NoSQL / prototype-pollution operator objects (checklist §5, §13). These are
# injected into object-typed parameters; detection is best-effort (error-based)
# and these usually need manual confirmation.
NOSQL_OBJECTS = [
    {"$ne": None},
    {"$gt": ""},
    {"$where": "true"},
]
PROTOTYPE_POLLUTION = [
    {"__proto__": {"mcpdxPolluted": True}},
    {"constructor": {"prototype": {"mcpdxPolluted": True}}},
]

# Custom / client URI schemes that can be abused via URL parameters (§13).
URI_SCHEMES = [
    "file:///etc/passwd",
    "vscode://file/etc/passwd",
    "atlas://mcpdx/probe",
]

COMMAND_INJECTION = [
    "; echo MCPDX_$((1337*3))",
    "| echo MCPDX_$((1337*3))",
    "$(echo MCPDX_$((1337*3)))",
    "`echo MCPDX_4011`",
    "& echo MCPDX_4011",
    "\n echo MCPDX_4011",
]
# 1337*3 == 4011: if math is evaluated by a shell we see the literal 4011.
COMMAND_INJECTION_INDICATORS = [re.compile(r"MCPDX_4011")]

SSRF = [
    "http://169.254.169.254/latest/meta-data/",       # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1:80/",
    "http://localhost/",
    "file:///etc/passwd",
]
SSRF_INDICATORS = [
    re.compile(r"ami-id|instance-id|iam/security-credentials", re.I),
    re.compile(r"computeMetadata", re.I),
]

# Generic over-long / type-confusion inputs for robustness probing.
ROBUSTNESS = [
    "A" * 10000,
    "",
    "\x00\x01\x02",
    "%n%n%n%s%s%s",
    "{{7*7}}",      # template injection
    "${{7*7}}",
    "{constructor.constructor('return 1')()}",
    "null",
    -1,
    2 ** 63,
]

# --------------------------------------------------------------------------- #
#  Known-vulnerable component signatures                                       #
# --------------------------------------------------------------------------- #
# Matched against the server's advertised name/version (serverInfo) and the
# implementation strings it reports. `version_lt` flags anything *below* the
# fixed version. Extend this table as new MCP CVEs are published.
KNOWN_VULNS = [
    {
        "match": ["mcp-inspector", "mcp inspector", "inspector"],
        "version_lt": "0.14.1",
        "cve": "CVE-2025-49596",
        "severity": "CRITICAL",
        "desc": "MCP Inspector accepted unverified input allowing remote code "
                "execution via crafted messages; fixed in 0.14.1.",
        "fix": "Upgrade MCP Inspector to >= 0.14.1.",
    },
    {
        "match": ["secure-filesystem-server", "filesystem-server", "server-filesystem"],
        "version_lt": "2025.7.1",
        "cve": "CVE-2025-53109 / CVE-2025-53110 (EscapeRoute)",
        "severity": "HIGH",
        "desc": "Anthropic Filesystem MCP server allowed agents to escape the "
                "allowed-directory scope via prefix-match path validation and "
                "symlink following, yielding arbitrary file read/write. Fixed in "
                "npm 2025.7.1 (and legacy branch 0.6.4).",
        "fix": "Upgrade @modelcontextprotocol/server-filesystem to >= 2025.7.1 "
               "(or >= 0.6.4 on the legacy line); verify the reported version.",
    },
    {
        "match": ["mcp-server-git", "git-mcp-server", "mcp_server_git"],
        "version_lt": "2025.12.18",
        "cve": "CVE-2025-68143 / CVE-2025-68144 / CVE-2025-68145",
        "severity": "HIGH",
        "desc": "Anthropic Git MCP server RCE chain: --repository path not enforced "
                "per call (68145), user-controlled args reaching GitPython enabled "
                "arbitrary file overwrite via git_diff --output (68144), and git_init "
                "could turn any directory into a repo (68143). Fixed in 2025.12.18.",
        "fix": "Upgrade mcp-server-git to >= 2025.12.18.",
    },
    {
        # mcp-remote is a client-side proxy; flagged here in case its identity is
        # surfaced through a chained serverInfo.
        "match": ["mcp-remote"],
        "version_lt": "0.1.16",
        "cve": "CVE-2025-6514",
        "severity": "CRITICAL",
        "desc": "mcp-remote passed an OAuth authorization_endpoint URL into the OS "
                "`open()` handler without sanitization, letting a malicious server "
                "trigger arbitrary command execution on the client. Fixed in 0.1.16.",
        "fix": "Upgrade mcp-remote to >= 0.1.16 and only connect to trusted servers "
               "over HTTPS.",
    },
]


def parse_version(v):
    """Return a comparable tuple of leading integer components of a version."""
    nums = re.findall(r"\d+", str(v or ""))
    return tuple(int(n) for n in nums) or (0,)


def version_lt(a, b) -> bool:
    """True if version a < version b (numeric-component comparison)."""
    ta, tb = parse_version(a), parse_version(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta < tb


# Substrings in error output that hint at info disclosure.
INFO_DISCLOSURE_INDICATORS = [
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)"),          # java stack
    re.compile(r"\b(?:[A-Za-z]:\\|/(?:home|root|usr|var)/)[^\s\"']+"),  # paths
    re.compile(r"(?i)\b(stack ?trace|exception in thread)\b"),
    re.compile(r"(?i)(sqlstate|syntax error at or near|ORA-\d{5})"),
]

# Secret / credential patterns to flag if they appear in tool OUTPUT or errors
# (checklist §6, §10). (label, regex). Conservative to limit false positives.
SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r"(?i)aws.{0,20}secret.{0,3}[:=].{0,3}[A-Za-z0-9/+]{40}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprse]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    # GitHub fine-grained PATs use a distinct, longer prefix (since 2022).
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    # AI-provider keys — high-value in an MCP/agent context (a leaked key here
    # hands an attacker the model budget and any data the agent can reach).
    ("Anthropic API key", re.compile(r"(?<![\w-])sk-ant-[A-Za-z0-9-]{20,}")),
    ("OpenAI API key", re.compile(r"(?<![\w-])sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}")),
    # Legacy OpenAI keys carry a fixed 'T3BlbkFJ' infix — a very low-FP signal.
    ("OpenAI API key (legacy)", re.compile(r"\bsk-[A-Za-z0-9_-]{8,}T3BlbkFJ[A-Za-z0-9_-]{8,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("GitLab PAT", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("Stripe secret key", re.compile(r"\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Generic API key assignment", re.compile(r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]


def scan_secrets(text: str):
    """Return [(label, matched_snippet)] for any secret patterns found in text."""
    hits = []
    for label, rx in SECRET_PATTERNS:
        m = rx.search(text or "")
        if m:
            snippet = m.group(0)
            if len(snippet) > 12:  # redact the middle of the match
                snippet = snippet[:6] + "…" + snippet[-4:]
            hits.append((label, snippet))
    return hits
