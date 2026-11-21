"""Semgrep CE adapter (P0): `semgrep scan --config <cfg> --sarif --metrics=off <path>`.

License: LGPL-2.1 (engine); rule-pack licensing is separate (registry packs: verify).
Version 1.176.1 is the documented tested pin; it is NOT enforced unless `version` is set in cfg.
Config: default `p/security-audit` (registry, NEEDS NETWORK). Set cfg `config` to a local rules
file/dir for offline use. With a registry config and no network the result is SKIPPED with a
clear detail, never a silent clean result.
Invocation follows ~/src/synth/scripts/run_scanners.sh (`--config=p/security-audit --sarif`);
we add --metrics=off and --disable-version-check so nothing phones home, and run in a scratch
cwd. Semgrep exits 0 with `executionSuccessful: true` even for an invalid/unreachable config,
so toolExecutionNotifications of level error are inspected explicitly.
Files analyzed is parsed from semgrep's "Ran N rules on M files" line, falling back to a file count.
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters._resolve import rel_uri, resolve_exe
from kaleidoscan.adapters.base import (
    ScannerInfo, ScannerKind, ScannerResult, ScannerStatus, Stopwatch, Target, cfg_get,
    count_files, result,
)
from kaleidoscan.runner import redact, run_command, safe_path_arg

ID = "semgrep"
DEFAULT_CONFIG = "p/security-audit"
PINNED_VERSION = "1.176.1"  # documented, not enforced
LANG_EXTS = {
    "python": (".py",), "go": (".go",), "java": (".java",), "csharp": (".cs",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"), "typescript": (".ts", ".tsx"),
    "ruby": (".rb",), "php": (".php",), "c": (".c", ".h"), "cpp": (".cc", ".cpp", ".hpp"),
    "rust": (".rs",), "kotlin": (".kt",), "scala": (".scala",), "swift": (".swift",),
}
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)")
_RAN_RE = re.compile(r"Ran \d+ rules? on (\d+) files?")
_NET_RE = re.compile(r"(?i)(failed to download|could not resolve|name or service not known|"
                     r"connection (?:error|refused|reset)|network is unreachable|timed out|"
                     r"max retries|temporary failure|certificate verify|ssl|unable to reach|"
                     r"semgrep\.dev)")


def parse_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def resolve_binary(cfg=None, env=None):
    return resolve_exe("semgrep", cfg, env)


def _is_registry(config: str) -> bool:
    return not Path(config).expanduser().exists()


class SemgrepAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SAST, languages=frozenset(LANG_EXTS),
                       license="LGPL-2.1", restricted=False, offline_capable=False)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None):
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    @staticmethod
    def _version(argv) -> str | None:
        r = run_command([*argv, "--version", "--disable-version-check"], timeout_s=30, max_output_bytes=4096)
        return parse_version(r.stdout.decode("utf-8", "replace")) if r.returncode == 0 else None

    def detect(self) -> tuple[bool, str | None]:
        argv = self._argv()
        if not argv:
            return False, None
        v = self._version(argv)
        return (v is not None), v

    def applicable(self, t: Target) -> bool:
        if t.kind not in ("repo", "dir"):
            return False
        return not t.languages or bool(t.languages & self.info.languages)

    def run(self, t: Target, cfg, *, timeout_s: int) -> ScannerResult:
        sw = Stopwatch()
        err = lambda st, d, v=None, f=None: result(ID, st, version=v, files=f, ms=sw.ms, detail=d)  # noqa: E731
        argv = self._argv(cfg)
        if not argv:
            return err(ScannerStatus.SKIPPED, "semgrep not found (set SEMGREP_BIN or install semgrep 1.176.1)")
        version = self._version(argv)
        if version is None:
            return err(ScannerStatus.ERROR, "semgrep --version failed")
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        exts = [e for ex in LANG_EXTS.values() for e in ex]
        counted = count_files(path, exts)
        if counted == 0:
            return err(ScannerStatus.EMPTY, "no files in a Semgrep-supported language in target", version, 0)
        config = str(cfg_get(cfg, "config") or DEFAULT_CONFIG)
        registry = _is_registry(config)
        with tempfile.TemporaryDirectory(prefix="kscan-semgrep-") as scratch:
            r = run_command([*argv, "scan", f"--config={config}", "--sarif", "--metrics=off",
                             "--disable-version-check", safe_path_arg(path)],
                            timeout_s=timeout_s, cwd=scratch)
        stderr = r.stderr.decode("utf-8", "replace")
        if r.timed_out:
            return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s", version, counted)
        if r.error or r.returncode != 0:
            msg = redact(r.error or f"exit {r.returncode}: " + r.stderr_tail())
            if registry and _NET_RE.search(stderr):
                return err(ScannerStatus.SKIPPED, "registry config needs network (offline?): " + msg, version, counted)
            return err(ScannerStatus.ERROR, msg, version, counted)
        if r.stdout_truncated:
            return err(ScannerStatus.ERROR, "SARIF output exceeded size cap", version, counted)
        try:
            log = json.loads(r.stdout)
        except ValueError as e:
            return err(ScannerStatus.ERROR, f"invalid JSON from semgrep: {e}", version, counted)
        problems = sarif_mod.validate(log)
        if problems:
            return err(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(problems[:3]), version, counted)
        errs = [n["message"]["text"] for run in log["runs"] for inv in run.get("invocations", [])
                for n in inv.get("toolExecutionNotifications", [])
                if n.get("level") == "error" and isinstance(n.get("message"), dict)
                and isinstance(n["message"].get("text"), str)]
        if errs:
            msg = redact("; ".join(errs))[:400]
            if registry and (_NET_RE.search(msg) or _NET_RE.search(stderr)):
                return err(ScannerStatus.SKIPPED, "registry config needs network (offline?): " + msg, version, counted)
            return err(ScannerStatus.ERROR, "semgrep reported errors: " + msg, version, counted)
        m = _RAN_RE.search(stderr)
        files = int(m.group(1)) if m else counted
        if files == 0:
            return err(ScannerStatus.EMPTY, "semgrep analyzed 0 files", version, 0)
        for run in log["runs"]:  # remap absolute URIs to target-relative (cf. remap_scanner_output.py)
            for res in run.get("results", []):
                for loc in res.get("locations", []):
                    al = loc.get("physicalLocation", {}).get("artifactLocation")
                    if isinstance(al, dict) and isinstance(al.get("uri"), str):
                        al["uri"] = rel_uri(al["uri"], path if path.is_dir() else path.parent)
        return result(ID, ScannerStatus.OK, version=version, files=files, sarif=log, ms=sw.ms,
                      detail=f"config={config}")
