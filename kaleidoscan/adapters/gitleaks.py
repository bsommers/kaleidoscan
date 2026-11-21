"""Gitleaks adapter (secrets): `gitleaks detect --no-git --source <path> --report-format sarif
--report-path <scratch file> --redact --exit-code 0` (MIT).

`detect` is deprecated since v8.19.0 (hidden from --help, still functional; `gitleaks dir` is the
successor), but we keep `detect --no-git` for the pinned-compatible invocation; see spec/research.md.

REDACTION IS MANDATORY: `--redact` is always passed (gitleaks then writes "REDACTED" as the
finding secret / SARIF snippet) and, as defence in depth, every string in the returned SARIF is
additionally scrubbed with kaleidoscan.redact and every snippet is replaced outright. No raw secret
may reach ScannerResult.sarif or .detail. The report is written to a file in a scratch directory
that is deleted on exit, so a secret never lands in the scanned repo or our cwd.
`files_analyzed` counts non-vendor files in the target (gitleaks does not report it); 0 => EMPTY.
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
from kaleidoscan.redact import REDACTED, redact as scrub_text
from kaleidoscan.runner import redact, run_command, safe_path_arg

ID = "gitleaks"
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)")
MAX_REPORT_BYTES = 64 * 1024 * 1024


def parse_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def resolve_binary(cfg=None, env=None):
    return resolve_exe("gitleaks", cfg, env)


def scrub_sarif(log: dict, root: Path | None = None) -> dict:
    """Return a copy of the SARIF log with every secret-looking string redacted, all region
    snippets replaced by [REDACTED], and (if root given) artifact URIs made root-relative."""
    def walk(node, key=None):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k == "snippet" and isinstance(v, dict):
                    out[k] = {**{kk: walk(vv, kk) for kk, vv in v.items()}, "text": REDACTED}
                elif k == "uri" and isinstance(v, str) and root is not None:
                    out[k] = rel_uri(v, root)
                else:
                    out[k] = walk(v, k)
            return out
        if isinstance(node, list):
            return [walk(x, key) for x in node]
        if isinstance(node, str):
            return scrub_text(node)[0]
        return node
    return walk(log)


class GitleaksAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SECRETS, languages=frozenset(),
                       license="MIT", restricted=False, offline_capable=True)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None):
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    @staticmethod
    def _version(argv) -> str | None:
        r = run_command([*argv, "version"], timeout_s=30, max_output_bytes=4096)
        return parse_version(r.stdout.decode("utf-8", "replace")) if r.returncode == 0 else None

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
            return err(ScannerStatus.SKIPPED, "gitleaks not found (set GITLEAKS_BIN or install gitleaks)")
        version = self._version(argv)
        if version is None:
            return err(ScannerStatus.ERROR, "gitleaks version failed")
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        counted = count_files(path, [""])  # every file; "" matches any name
        if counted == 0:
            return err(ScannerStatus.EMPTY, "no files in target", version, 0)
        with tempfile.TemporaryDirectory(prefix="kscan-gitleaks-") as scratch:
            report = Path(scratch) / "report.sarif"
            r = run_command(
                [*argv, "detect", "--no-git", "--source", safe_path_arg(path),
                 "--report-format", "sarif", "--report-path", str(report),
                 "--redact", "--exit-code", "0", "--no-banner"],
                timeout_s=timeout_s, cwd=scratch)
            raw = None
            if report.is_file():
                if report.stat().st_size > MAX_REPORT_BYTES:
                    return err(ScannerStatus.ERROR, "SARIF report exceeded size cap", version, counted)
                raw = report.read_bytes()
        if r.timed_out:
            return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s", version, counted)
        if r.error or r.returncode != 0:
            return err(ScannerStatus.ERROR, redact(r.error or f"exit {r.returncode}: " + r.stderr_tail()), version, counted)
        if not raw:
            return err(ScannerStatus.ERROR, "gitleaks wrote no SARIF report", version, counted)
        try:
            log = json.loads(raw)
        except ValueError as e:
            return err(ScannerStatus.ERROR, f"invalid JSON from gitleaks: {e}", version, counted)
        log = scrub_sarif(log, path if path.is_dir() else path.parent) if isinstance(log, dict) else log
        problems = sarif_mod.validate(log)
        if problems:
            return err(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(problems[:3]), version, counted)
        return result(ID, ScannerStatus.OK, version=version, files=counted, sarif=log, ms=sw.ms,
                      detail=redact(r.stderr_tail(200).strip()))
