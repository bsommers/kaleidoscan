"""`kaleidoscan doctor`: tool availability + versions (C5). argv-only subprocess, never a shell."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass

from kaleidoscan import __version__

# (id, executable, required). Required tools make `doctor --strict` exit 3 when missing (P0 scanner).
TOOLS: tuple[tuple[str, str, bool], ...] = (
    ("flowscope", "flowscope", True),
    ("semgrep", "semgrep", False),
    ("bandit", "bandit", False),
    ("gosec", "gosec", False),
    ("gitleaks", "gitleaks", False),
    ("osv-scanner", "osv-scanner", False),
)
VERSION_TIMEOUT_S = 10
SCHEMA = "kaleidoscan.doctor/1"


@dataclass
class ToolReport:
    id: str
    required: bool
    status: str  # ok | missing | error
    path: str | None = None
    version: str | None = None
    channel: str | None = None  # how it was resolved: FLOWSCOPE_BIN | PATH
    detail: str = ""


def _probe(path: str) -> tuple[str, str | None, str]:
    try:
        p = subprocess.run([path, "--version"], capture_output=True, text=True,
                           timeout=VERSION_TIMEOUT_S, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return "error", None, f"--version timed out after {VERSION_TIMEOUT_S}s"
    except OSError as e:
        return "error", None, f"cannot execute: {e.strerror or e}"
    text = (p.stdout or p.stderr).strip()
    first = text.splitlines()[0] if text else ""
    if p.returncode != 0:
        return "error", None, f"--version exited {p.returncode}: {first[:120]}"
    return "ok", first or None, ""


def check_tool(tool_id: str, exe: str, required: bool) -> ToolReport:
    path, channel = None, None
    if tool_id == "flowscope" and os.environ.get("FLOWSCOPE_BIN"):
        path, channel = os.environ["FLOWSCOPE_BIN"], "FLOWSCOPE_BIN"
        if not (os.path.isfile(path) and os.access(path, os.X_OK)):
            return ToolReport(tool_id, required, "error", path, None, channel,
                              "FLOWSCOPE_BIN is not an executable file")
    else:
        path = shutil.which(exe)
        channel = "PATH"
    if path is None:
        return ToolReport(tool_id, required, "missing", None, None, None, f"{exe} not found on PATH")
    status, version, detail = _probe(path)
    return ToolReport(tool_id, required, status, path, version, channel, detail)


def collect() -> dict:
    tools = [check_tool(*t) for t in TOOLS]
    return {
        "schema": SCHEMA,
        "version": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "tools": [asdict(t) for t in tools],
    }


def required_failures(report: dict) -> list[str]:
    return [t["id"] for t in report["tools"] if t["required"] and t["status"] != "ok"]


def render_text(report: dict) -> str:
    lines = [f"kaleidoscan {report['version']}  python {report['python']}  {report['platform']}", ""]
    for t in report["tools"]:
        mark = {"ok": "ok     ", "missing": "MISSING", "error": "ERROR  "}[t["status"]]
        req = " (required)" if t["required"] else ""
        extra = t["version"] or t["detail"]
        lines.append(f"  {mark} {t['id']:<12}{req} {extra}".rstrip())
    bad = required_failures(report)
    lines += ["", "required tools: " + ("all present" if not bad else "missing/failed: " + ", ".join(bad))]
    return "\n".join(lines) + "\n"


def run(as_json: bool, strict: bool) -> int:
    import json

    report = collect()
    sys.stdout.write(json.dumps(report, indent=2) + "\n" if as_json else render_text(report))
    if strict and required_failures(report):
        if as_json:
            print("required tool missing: " + ", ".join(required_failures(report)), file=sys.stderr)
        return 3
    return 0
