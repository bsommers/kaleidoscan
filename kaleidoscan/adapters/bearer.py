"""Bearer CLI adapter: `bearer scan <path> --format sarif`.

License (verified from github.com/Bearer/bearer LICENSE.txt, 2026-11): Elastic License 2.0 --
source-available, NOT OSI open source. Local/internal scanning is permitted; the ELv2
limitations (no hosted/managed-service offering, no circumventing license-key functionality)
do not apply to running it as a CLI here. Recorded honestly as license="Elastic-2.0".
`restricted` stays False (no per-use opt-in needed, unlike CodeQL) but doctor should surface
the license string.

Invocation reuses the proven one from synth/scripts/run_scanners.sh (bearer scan, sarif),
hardened for kaleidoscan: update/version check disabled (offline-safe), progress/quiet, forced
exit code 0 (findings must not look like a crash), SARIF read from stdout.
Binary resolution: `bin` cfg, $BEARER_BIN, synth scanners clone ($SYNTH_SCANNERS or
~/src/synth/.scanners/bin/bearer), then PATH.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.base import (
    ScannerInfo, ScannerKind, ScannerResult, ScannerStatus, Stopwatch, Target, cfg_get,
    count_files, result,
)
from kaleidoscan.runner import redact, run_command, safe_path_arg

ID = "bearer"
LANG_EXTS = {
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
    "ruby": (".rb",),
    "java": (".java",),
    "php": (".php",),
    "go": (".go",),
}
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)")


def _is_exe(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


def resolve_binary(cfg=None, env=None) -> tuple[list[str] | None, str]:
    env = os.environ if env is None else env
    explicit = cfg_get(cfg, "bin") or env.get("BEARER_BIN")
    if explicit:
        p = Path(explicit).expanduser()
        return ([str(p)], "explicit") if _is_exe(p) else (None, "explicit")
    scanners = Path(env.get("SYNTH_SCANNERS") or "~/src/synth/.scanners").expanduser()
    p = scanners / "bin" / "bearer"
    if _is_exe(p):
        return [str(p)], "clone"
    found = shutil.which("bearer", path=env.get("PATH"))
    return ([found], "path") if found else (None, "path")


def parse_version(text: str) -> str | None:
    """`bearer version 2.1.1, build ...` -> 2.1.1 (ignores the 'outdated version' banner's v2.1.3)."""
    m = re.search(r"bearer version\s+(\d+\.\d+\.\d+(?:[-+][\w.]+)?)", text)
    if m:
        return m.group(1)
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


class BearerAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SAST, languages=frozenset(LANG_EXTS),
                       license="Elastic-2.0", restricted=False, offline_capable=True)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None) -> list[str] | None:
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    @staticmethod
    def detect_with(argv: list[str]) -> tuple[bool, str | None]:
        r = run_command([*argv, "version", "--disable-version-check"], timeout_s=20, max_output_bytes=8192)
        if r.returncode != 0:
            return False, None
        return True, parse_version((r.stdout + r.stderr).decode("utf-8", "replace"))

    def detect(self) -> tuple[bool, str | None]:
        argv = self._argv()
        return self.detect_with(argv) if argv else (False, None)

    def applicable(self, t: Target) -> bool:
        if t.kind not in ("repo", "dir"):
            return False
        return not t.languages or bool(t.languages & self.info.languages)

    def run(self, t: Target, cfg, *, timeout_s: int) -> ScannerResult:
        sw = Stopwatch()
        err = lambda st, d, v=None, f=None: result(ID, st, version=v, files=f, ms=sw.ms, detail=d)  # noqa: E731
        argv = self._argv(cfg)
        if not argv:
            return err(ScannerStatus.SKIPPED, "bearer not found (set BEARER_BIN or install Bearer CLI)")
        _, version = self.detect_with(argv)
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        files = count_files(path, [e for ex in LANG_EXTS.values() for e in ex])
        if files == 0:
            return err(ScannerStatus.EMPTY, "no Python/JS/TS/Ruby/Java/PHP/Go files in target", version, 0)
        with tempfile.TemporaryDirectory(prefix="kscan-bearer-") as scratch:
            r = run_command(
                [*argv, "scan", "--format", "sarif", "--scanner=sast", "--quiet", "--hide-progress-bar",
                 "--disable-version-check", "--disable-domain-resolution", "--no-color",
                 "--exit-code", "0", safe_path_arg(path)],
                timeout_s=timeout_s, cwd=scratch)
        if r.timed_out:
            return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s", version, files)
        if r.error or r.returncode != 0:
            return err(ScannerStatus.ERROR, redact(r.error or f"exit {r.returncode}: " + r.stderr_tail()), version, files)
        if r.stdout_truncated:
            return err(ScannerStatus.ERROR, "SARIF output exceeded size cap", version, files)
        try:
            log = json.loads(r.stdout)
        except ValueError as e:
            return err(ScannerStatus.ERROR, f"invalid JSON from bearer: {e}", version, files)
        # Bearer emits `"results": null` when clean; normalise so it validates as an empty list.
        for run in log.get("runs", []) if isinstance(log, dict) and isinstance(log.get("runs"), list) else []:
            if isinstance(run, dict) and run.get("results") is None:
                run["results"] = []
        problems = sarif_mod.validate(log)
        if problems:
            return err(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(problems[:3]), version, files)
        return result(ID, ScannerStatus.OK, version=version, files=files, sarif=log, ms=sw.ms,
                      detail=redact(r.stderr_tail(200).strip()))
