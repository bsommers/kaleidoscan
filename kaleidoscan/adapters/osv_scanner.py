"""OSV-Scanner adapter (SCA): `osv-scanner scan source --format sarif -r <path>` (Apache-2.0).

Flags verified against google/osv-scanner docs (usage.md, scan-source.md, output.md) and
cmd/osv-scanner/internal/cmd/run.go exit-code mapping, see spec/research.md:
  exit 0 clean, 1 vulnerabilities found (still valid SARIF on stdout), 127 generic error,
  128 no package sources found (=> EMPTY), 129 vulnerability API failed (=> SKIPPED: needs network),
  130 invalid config.
Needs the OSV API (or a pre-downloaded offline DB), so offline_capable=False: when the API is
unreachable the adapter reports SKIPPED with a clear detail rather than a false "clean".
cfg `offline: true` adds `--offline` (requires a previously downloaded local database).
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters._resolve import resolve_exe
from kaleidoscan.adapters.base import (
    ScannerInfo, ScannerKind, ScannerResult, ScannerStatus, Stopwatch, Target, cfg_get, result,
)
from kaleidoscan.runner import redact, run_command, safe_path_arg

ID = "osv-scanner"
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)")
_NET_HINT = re.compile(r"(?i)(dial tcp|no such host|network is unreachable|connection refused|"
                       r"timeout|api.*fail|osv\.dev|offline)")


def parse_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def resolve_binary(cfg=None, env=None):
    return resolve_exe("osv-scanner", cfg, env)


class OsvScannerAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SCA, languages=frozenset(),
                       license="Apache-2.0", restricted=False, offline_capable=False)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None):
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    @staticmethod
    def _version(argv) -> str | None:
        r = run_command([*argv, "--version"], timeout_s=30, max_output_bytes=4096)
        # version text goes through osv-scanner's logger (possibly stderr), so read both
        text = (r.stdout + b"\n" + r.stderr).decode("utf-8", "replace")
        return parse_version(text) if r.returncode == 0 else None

    def detect(self) -> tuple[bool, str | None]:
        argv = self._argv()
        if not argv:
            return False, None
        v = self._version(argv)
        return (v is not None), v

    def applicable(self, t: Target) -> bool:
        return t.kind in ("repo", "dir")

    def run(self, t: Target, cfg, *, timeout_s: int) -> ScannerResult:
        sw = Stopwatch()
        err = lambda st, d, v=None, f=None: result(ID, st, version=v, files=f, ms=sw.ms, detail=d)  # noqa: E731
        argv = self._argv(cfg)
        if not argv:
            return err(ScannerStatus.SKIPPED, "osv-scanner not found (set OSV_SCANNER_BIN or install osv-scanner)")
        version = self._version(argv)
        if version is None:
            return err(ScannerStatus.ERROR, "osv-scanner --version failed")
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        flags = ["--format", "sarif"]
        if cfg_get(cfg, "offline"):
            flags.append("--offline")
        with tempfile.TemporaryDirectory(prefix="kscan-osv-") as scratch:
            r = run_command([*argv, "scan", "source", *flags, "-r", safe_path_arg(path)],
                            timeout_s=timeout_s, cwd=scratch)
        if r.timed_out:
            return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s", version)
        stderr = r.stderr_tail()
        if r.error:
            return err(ScannerStatus.ERROR, redact(r.error), version)
        if r.returncode == 128:
            return err(ScannerStatus.EMPTY, "no lockfiles or package manifests found in target", version, 0)
        if r.returncode == 129 or (r.returncode not in (0, 1) and _NET_HINT.search(stderr)):
            return err(ScannerStatus.SKIPPED,
                       "OSV vulnerability database unreachable (offline?): " + stderr[-200:].strip(), version)
        if r.returncode not in (0, 1):
            return err(ScannerStatus.ERROR, f"exit {r.returncode}: {stderr}", version)
        if r.stdout_truncated:
            return err(ScannerStatus.ERROR, "SARIF output exceeded size cap", version)
        try:
            log = json.loads(r.stdout)
        except ValueError as e:
            return err(ScannerStatus.ERROR, f"invalid JSON from osv-scanner: {e}", version)
        problems = sarif_mod.validate(log)
        if problems:
            return err(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(problems[:3]), version)
        # one SARIF artifact per scanned lockfile/manifest => the analyzed-package-source count
        files = sum(len(run.get("artifacts") or []) for run in log.get("runs", []))
        return result(ID, ScannerStatus.OK, version=version, files=files or None, sarif=log, ms=sw.ms,
                      detail="")
