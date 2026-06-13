"""Verbosity-aware, colorized logger used across mcpdx.

Verbosity levels (set from the CLI):
    -2  quiet   : only ERROR / results
    -1  ...     : (unused gap kept for symmetry)
     0  normal  : INFO and above (default)
     1  -v      : DEBUG (protocol-level chatter)
     2  -vv      : TRACE (raw JSON-RPC frames)
"""

from __future__ import annotations

import sys
import time
from datetime import datetime


# --- ANSI handling -----------------------------------------------------------

class _C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"
    BRED = "\033[91m"
    BGREEN = "\033[92m"
    BYELLOW = "\033[93m"
    BCYAN = "\033[96m"
    WHITE = "\033[97m"


def _enable_windows_vt() -> None:
    """Turn on ANSI escape processing in legacy Windows consoles."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004 on the output handle
        for handle_id in (-11, -12):  # STDOUT, STDERR
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


# Severity -> (label, color)
LEVELS = {
    "TRACE": (_C.GREY, "trace"),
    "DEBUG": (_C.CYAN, "debug"),
    "INFO": (_C.BLUE, "info "),
    "OK": (_C.BGREEN, "ok   "),
    "WARN": (_C.BYELLOW, "warn "),
    "ERROR": (_C.BRED, "error"),
}


class Logger:
    QUIET = -2
    NORMAL = 0
    VERBOSE = 1
    TRACE_LVL = 2

    def __init__(self, verbosity: int = 0, color: bool = True, stream=None):
        self.verbosity = verbosity
        self.color = color
        self.stream = stream or sys.stderr
        self._t0 = time.monotonic()
        if color:
            _enable_windows_vt()

    # -- helpers --------------------------------------------------------------
    def c(self, text: str, *codes: str) -> str:
        if not self.color:
            return text
        return "".join(codes) + text + _C.RESET

    def _emit(self, level: str, msg: str) -> None:
        color, label = LEVELS[level]
        elapsed = time.monotonic() - self._t0
        ts = self.c(f"{elapsed:7.3f}s", _C.GREY) if self.color else f"{elapsed:7.3f}s"
        tag = self.c(label, _C.BOLD, color) if self.color else label
        print(f"[{ts}] {tag} {msg}", file=self.stream, flush=True)

    # -- level gates ----------------------------------------------------------
    def error(self, msg: str) -> None:
        self._emit("ERROR", msg)

    def warn(self, msg: str) -> None:
        if self.verbosity > self.QUIET:
            self._emit("WARN", msg)

    def ok(self, msg: str) -> None:
        if self.verbosity > self.QUIET:
            self._emit("OK", msg)

    def info(self, msg: str) -> None:
        if self.verbosity >= self.NORMAL:
            self._emit("INFO", msg)

    def debug(self, msg: str) -> None:
        if self.verbosity >= self.VERBOSE:
            self._emit("DEBUG", msg)

    def trace(self, msg: str) -> None:
        if self.verbosity >= self.TRACE_LVL:
            # Keep raw frames compact-ish but readable.
            self._emit("TRACE", msg)

    @property
    def is_trace(self) -> bool:
        return self.verbosity >= self.TRACE_LVL

    # -- user-facing plain output (always to stdout, not the log stream) ------
    def out(self, msg: str = "") -> None:
        print(msg, flush=True)
