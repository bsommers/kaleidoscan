"""Flowscope adapter (P0): `flowscope scan <path> --format sarif`.

Binary resolution (C17, local channels only; installer/container are not built because
Flowscope publishes neither yet, see bsommers/flowscope#22):
  1. `bin` in the scanner config, 2. $FLOWSCOPE_BIN, 3. a built clone
  ($FLOWSCOPE_REPO or ~/src/flowscope, `target/release/flowscope`, honouring $CARGO_TARGET_DIR),
  4. `flowscope` on PATH.
Flowscope does not report how many files it analyzed, so `files_analyzed` is counted from
the target's supported-language files; zero means EMPTY, never "clean".
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

ID = "flowscope"
# language name -> source extensions Flowscope analyzes (verified on 0.4.5; rust/java: flowscope#20/#21)
LANG_EXTS = {
    "python": (".py",),
    "go": (".go",),
    "javascript": (".js", ".jsx", ".mjs", ".cjs"),
    "typescript": (".ts", ".tsx"),
}
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)")


def _is_exe(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


def resolve_binary(cfg=None, env=None) -> tuple[list[str] | None, str]:
    """Return (argv_prefix, channel). argv_prefix is None when nothing usable is found."""
    env = os.environ if env is None else env
    explicit = cfg_get(cfg, "bin") or env.get("FLOWSCOPE_BIN")
    if explicit:
        p = Path(explicit).expanduser()
        return ([str(p)], "explicit") if _is_exe(p) else (None, "explicit")
    repo = Path(env.get("FLOWSCOPE_REPO") or "~/src/flowscope").expanduser()
    for base in filter(None, [env.get("CARGO_TARGET_DIR"), str(repo / "target")]):
        p = Path(base) / "release" / "flowscope"
        if _is_exe(p):
            return [str(p)], "clone"
    found = shutil.which("flowscope", path=env.get("PATH"))
    return ([found], "path") if found else (None, "path")


def parse_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


class FlowscopeAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SAST, languages=frozenset(LANG_EXTS),
                       license="Apache-2.0", restricted=False, offline_capable=True)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None) -> list[str] | None:
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    def detect(self) -> tuple[bool, str | None]:
        argv = self._argv()
        if not argv:
            return False, None
        r = run_command([*argv, "--version"], timeout_s=15, max_output_bytes=4096)
        if r.returncode != 0:
            return False, None
        return True, parse_version(r.stdout.decode("utf-8", "replace"))

    def applicable(self, t: Target) -> bool:
        if t.kind not in ("repo", "dir"):
            return False
        return not t.languages or bool(t.languages & self.info.languages)

    def run(self, t: Target, cfg, *, timeout_s: int) -> ScannerResult:
        sw = Stopwatch()
        err = lambda st, d, v=None, f=None: result(ID, st, version=v, files=f, ms=sw.ms, detail=d)  # noqa: E731
        argv = self._argv(cfg)
        if not argv:
            return err(ScannerStatus.SKIPPED, "flowscope not found (set FLOWSCOPE_BIN or build ~/src/flowscope)")
        _, version = self.detect_with(argv)
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()  # absolute: also defuses option injection via leading '-'
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        files = count_files(path, [e for ex in LANG_EXTS.values() for e in ex])
        if files == 0:
            return err(ScannerStatus.EMPTY, "no Python/Go/JavaScript/TypeScript files in target", version, 0)
        # Flowscope writes a `.flowscope/` cache in its cwd; run it in a scratch dir so the
        # scanned repo (and our own cwd) is never modified.
        with tempfile.TemporaryDirectory(prefix="kscan-flowscope-") as scratch:
            r = run_command([*argv, "scan", "--no-banner", "--format", "sarif", safe_path_arg(path)],
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
            return err(ScannerStatus.ERROR, f"invalid JSON from flowscope: {e}", version, files)
        problems = sarif_mod.validate(log)
        if problems:
            return err(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(problems[:3]), version, files)
        # zero findings over >0 analyzed files is a genuine clean result (OK), not EMPTY
        return result(ID, ScannerStatus.OK, version=version, files=files, sarif=log, ms=sw.ms,
                      detail=r.stderr_tail(200).strip())

    @staticmethod
    def detect_with(argv: list[str]) -> tuple[bool, str | None]:
        r = run_command([*argv, "--version"], timeout_s=15, max_output_bytes=4096)
        if r.returncode != 0:
            return False, None
        return True, parse_version(r.stdout.decode("utf-8", "replace"))
