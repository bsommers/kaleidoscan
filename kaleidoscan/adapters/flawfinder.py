"""Flawfinder adapter (C/C++ SAST, GPL-2.0): `flawfinder --sarif <path>`.

Flawfinder exits 0 even when it reports findings (verified on 2.0.20), so any non-zero exit is
an ERROR. It does not report how many files it analyzed, so `files_analyzed` is counted from the
target's C/C++ source files; zero means EMPTY, never "clean". Absolute artifact URIs under the
target are rewritten to target-relative paths. GPL-2.0: run as a separate process only.

Binary resolution: `bin` in config, $FLAWFINDER_BIN, `flawfinder` on PATH, then Synth's
$SYNTH_REPO/.scanners/venv/bin (default ~/src/synth).
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

ID = "flawfinder"
C_EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".c++", ".h++")
_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


def _is_exe(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


def resolve_binary(cfg=None, env=None) -> tuple[list[str] | None, str]:
    env = os.environ if env is None else env
    explicit = cfg_get(cfg, "bin") or env.get("FLAWFINDER_BIN")
    if explicit:
        p = Path(explicit).expanduser()
        return ([str(p)], "explicit") if _is_exe(p) else (None, "explicit")
    found = shutil.which("flawfinder", path=env.get("PATH"))
    if found:
        return [found], "path"
    home = Path(env.get("HOME") or Path.home())
    p = Path(env.get("SYNTH_REPO") or home / "src" / "synth") / ".scanners" / "venv" / "bin" / "flawfinder"
    return ([str(p)], "local") if _is_exe(p) else (None, "path")


def parse_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def relativize(log: dict, root: Path) -> None:
    """Rewrite absolute artifact URIs under `root` to root-relative posix paths, in place."""
    base = root.parent if root.is_file() else root

    def walk(o):
        if isinstance(o, dict):
            al = o.get("artifactLocation")
            if isinstance(al, dict) and isinstance(al.get("uri"), str):
                u = al["uri"][7:] if al["uri"].startswith("file://") else al["uri"]
                try:
                    al["uri"] = Path(u).relative_to(base).as_posix() if os.path.isabs(u) else u
                except ValueError:
                    pass
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(log)


class FlawfinderAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SAST, languages=frozenset({"c", "cpp"}),
                       license="GPL-2.0", restricted=False, offline_capable=True)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None) -> list[str] | None:
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    @staticmethod
    def detect_with(argv: list[str]) -> tuple[bool, str | None]:
        r = run_command([*argv, "--version"], timeout_s=15, max_output_bytes=4096)
        if r.returncode != 0:
            return False, None
        return True, parse_version(r.stdout.decode("utf-8", "replace"))

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
            return err(ScannerStatus.SKIPPED, "flawfinder not found (set FLAWFINDER_BIN or `pip install flawfinder`)")
        _, version = self.detect_with(argv)
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        files = count_files(path, C_EXTS)
        if files == 0:
            return err(ScannerStatus.EMPTY, "no C/C++ files in target", version, 0)
        with tempfile.TemporaryDirectory(prefix="kscan-flawfinder-") as scratch:
            r = run_command([*argv, "--sarif", safe_path_arg(path)], timeout_s=timeout_s, cwd=scratch)
        if r.timed_out:
            return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s", version, files)
        if r.error or r.returncode != 0:
            return err(ScannerStatus.ERROR, redact(r.error or f"exit {r.returncode}: " + r.stderr_tail()), version, files)
        if r.stdout_truncated:
            return err(ScannerStatus.ERROR, "SARIF output exceeded size cap", version, files)
        try:
            log = json.loads(r.stdout)
        except ValueError as e:
            return err(ScannerStatus.ERROR, f"invalid JSON from flawfinder: {e}", version, files)
        problems = sarif_mod.validate(log)
        if problems:
            return err(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(problems[:3]), version, files)
        relativize(log, path)
        return result(ID, ScannerStatus.OK, version=version, files=files, sarif=log, ms=sw.ms,
                      detail=redact(r.stderr_tail(200).strip()))
