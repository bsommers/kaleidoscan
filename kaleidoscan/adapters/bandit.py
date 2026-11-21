"""Bandit adapter (P0, Python): `bandit -r <path> -f json -q`, converted to SARIF 2.1.0 here
(Bandit core has no SARIF output; its SARIF formatter is a separate plugin we do not rely on).

License Apache-2.0. Tested pin 1.9.4 (documented, enforced only via cfg `version`).
Invocation/CWE handling follow ~/src/synth/scripts/run_scanners.sh and remap_scanner_output.py
(bandit: native JSON, each result carries issue_cwe.id). Exit codes: 0 clean, 1 issues found,
anything else is an error. `files_analyzed` comes from Bandit's own per-file metrics
(it counts files with zero issues too); 0 means EMPTY, never clean.
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

ID = "bandit"
PINNED_VERSION = "1.9.4"
_VERSION_RE = re.compile(r"bandit\s+(\d+\.\d+\.\d+(?:[-+][\w.]+)?)", re.I)
_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def parse_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def resolve_binary(cfg=None, env=None):
    return resolve_exe("bandit", cfg, env)


def bandit_json_to_sarif(doc: dict, root: Path, version: str | None = None) -> dict:
    """Convert Bandit `-f json` output to a SARIF 2.1.0 log. URIs become root-relative."""
    rules: dict[str, dict] = {}
    results = []
    for r in doc.get("results", []):
        rid = str(r.get("test_id") or "bandit")
        cwe = (r.get("issue_cwe") or {}).get("id")
        rule = rules.setdefault(rid, {
            "id": rid, "name": str(r.get("test_name") or rid),
            "shortDescription": {"text": str(r.get("test_name") or rid)},
            "helpUri": r.get("more_info") or "https://bandit.readthedocs.io/",
            "defaultConfiguration": {"level": _LEVEL.get(str(r.get("issue_severity")).upper(), "warning")},
            "properties": {"tags": ["security"] + ([f"CWE-{int(cwe)}"] if isinstance(cwe, int) else [])},
        })
        line = int(r.get("line_number") or 1)
        region = {"startLine": line}
        rng = r.get("line_range") or []
        if rng:
            region["endLine"] = int(max(rng))
        if isinstance(r.get("col_offset"), int):
            region["startColumn"] = r["col_offset"] + 1
        results.append({
            "ruleId": rid,
            "level": _LEVEL.get(str(r.get("issue_severity")).upper(), "warning"),
            "message": {"text": str(r.get("issue_text") or rule["name"])},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": rel_uri(str(r.get("filename", "")), root)},
                "region": region}}],
            "properties": {"confidence": str(r.get("issue_confidence", "")).lower(),
                           "cwe": f"CWE-{int(cwe)}" if isinstance(cwe, int) else None},
        })
    driver = {"name": "Bandit", "informationUri": "https://bandit.readthedocs.io/",
              "rules": list(rules.values())}
    if version:
        driver["version"] = version
    return {"version": "2.1.0", "$schema": sarif_mod.SARIF_SCHEMA,
            "runs": [{"tool": {"driver": driver}, "results": results}]}


class BanditAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SAST, languages=frozenset({"python"}),
                       license="Apache-2.0", restricted=False, offline_capable=True)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None):
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    @staticmethod
    def _version(argv) -> str | None:
        r = run_command([*argv, "--version"], timeout_s=30, max_output_bytes=4096)
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
        return not t.languages or "python" in t.languages

    def run(self, t: Target, cfg, *, timeout_s: int) -> ScannerResult:
        sw = Stopwatch()
        err = lambda st, d, v=None, f=None: result(ID, st, version=v, files=f, ms=sw.ms, detail=d)  # noqa: E731
        argv = self._argv(cfg)
        if not argv:
            return err(ScannerStatus.SKIPPED, "bandit not found (set BANDIT_BIN or install bandit 1.9.4)")
        version = self._version(argv)
        if version is None:
            return err(ScannerStatus.ERROR, "bandit --version failed")
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        counted = count_files(path, [".py"])
        if counted == 0:
            return err(ScannerStatus.EMPTY, "no Python files in target", version, 0)
        with tempfile.TemporaryDirectory(prefix="kscan-bandit-") as scratch:
            r = run_command([*argv, "-r", "-f", "json", "-q", safe_path_arg(path)],
                            timeout_s=timeout_s, cwd=scratch)
        if r.timed_out:
            return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s", version, counted)
        if r.error or r.returncode not in (0, 1):
            return err(ScannerStatus.ERROR, redact(r.error or f"exit {r.returncode}: " + r.stderr_tail()), version, counted)
        if r.stdout_truncated:
            return err(ScannerStatus.ERROR, "JSON output exceeded size cap", version, counted)
        try:
            doc = json.loads(r.stdout)
            if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
                raise ValueError("missing results array")
        except ValueError as e:
            return err(ScannerStatus.ERROR, f"invalid JSON from bandit: {e}", version, counted)
        metrics = doc.get("metrics") if isinstance(doc.get("metrics"), dict) else {}
        files = len([k for k in metrics if k != "_totals"]) if metrics else counted
        if files == 0:
            return err(ScannerStatus.EMPTY, "bandit analyzed 0 files", version, 0)
        root = path if path.is_dir() else path.parent
        log = bandit_json_to_sarif(doc, root, version)
        problems = sarif_mod.validate(log)
        if problems:
            return err(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(problems[:3]), version, files)
        nerr = len(doc.get("errors") or [])
        return result(ID, ScannerStatus.OK, version=version, files=files, sarif=log, ms=sw.ms,
                      detail=f"{nerr} file(s) failed to parse" if nerr else "")
