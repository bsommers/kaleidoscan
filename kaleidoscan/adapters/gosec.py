"""gosec adapter (Go SAST, Apache-2.0): `gosec -fmt=sarif -no-fail ./...` over a staged tree.

Why staging (documented by Synth, scripts/run_scanners.sh): gosec loads one Go package per
directory, so a tree whose files in one directory declare different packages (or that has no
go.mod / unbuildable pieces) silently yields "0 results". We therefore copy the target's .go
files into a scratch tree where every directory holds exactly one package, run gosec there
(`./...`, `-no-fail` so findings do not turn into exit 1), and map every SARIF path back to
the original target-relative path. A target with no analyzable .go files is EMPTY, never clean.

Binary resolution: `bin` in config, $GOSEC_BIN, `gosec` on PATH, $GOBIN, $GOPATH/bin,
~/go/bin, then Synth's $SYNTH_REPO/.scanners/bin (default ~/src/synth).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.base import (
    SKIP_DIRS, ScannerInfo, ScannerKind, ScannerResult, ScannerStatus, Stopwatch, Target,
    cfg_get, result,
)
from kaleidoscan.runner import redact, run_command

ID = "gosec"
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+(?:[-+][\w.]+)?)")
_PKG_RE = re.compile(rb"^\s*package\s+([A-Za-z_]\w*)", re.M)
_NO_GO_DIRS = SKIP_DIRS | {"vendor", "testdata"}
_MAX_STAGE_FILE = 8 * 1024 * 1024


def _is_exe(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


def resolve_binary(cfg=None, env=None) -> tuple[list[str] | None, str]:
    env = os.environ if env is None else env
    explicit = cfg_get(cfg, "bin") or env.get("GOSEC_BIN")
    if explicit:
        p = Path(explicit).expanduser()
        return ([str(p)], "explicit") if _is_exe(p) else (None, "explicit")
    found = shutil.which("gosec", path=env.get("PATH"))
    if found:
        return [found], "path"
    home = Path(env.get("HOME") or Path.home())
    dirs = [env.get("GOBIN"), *(f"{g}/bin" for g in (env.get("GOPATH") or "").split(os.pathsep) if g),
            str(home / "go" / "bin"),
            str(Path(env.get("SYNTH_REPO") or home / "src" / "synth") / ".scanners" / "bin")]
    for d in filter(None, dirs):
        p = Path(d) / "gosec"
        if _is_exe(p):
            return [str(p)], "local"
    return None, "path"


def parse_version(text: str) -> str | None:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def _go_files(root: Path) -> list[Path]:
    """Analyzable .go files (gosec skips _test.go by default), without following symlinks."""
    if root.is_file():
        return [root] if root.name.endswith(".go") and not root.name.endswith("_test.go") else []
    out: list[Path] = []
    for dp, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in _NO_GO_DIRS)
        for f in sorted(files):
            p = Path(dp) / f
            if f.endswith(".go") and not f.endswith("_test.go") and not p.is_symlink():
                out.append(p)
    return out


def _package_of(p: Path) -> str:
    try:
        with open(p, "rb") as fh:
            m = _PKG_RE.search(fh.read(_MAX_STAGE_FILE))
    except OSError:
        return "_unreadable"
    return m.group(1).decode() if m else "_nopkg"


def stage_tree(root: Path, stage: Path) -> dict[str, str]:
    """Copy root's .go files into `stage` so each staged dir holds one package.

    Returns {staged path relative to stage (posix): original path relative to root (posix)}.
    """
    base = root.parent if root.is_file() else root
    by_dir: dict[Path, list[tuple[Path, str]]] = {}
    for f in _go_files(root):
        by_dir.setdefault(f.parent, []).append((f, _package_of(f)))
    mapping: dict[str, str] = {}
    for d, entries in by_dir.items():
        rel = PurePosixPath(*d.relative_to(base).parts)
        multi = len({pkg for _, pkg in entries}) > 1
        for f, pkg in entries:
            sub = rel / pkg if multi else rel
            dest = stage.joinpath(*sub.parts, f.name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, dest)
            mapping[dest.relative_to(stage).as_posix()] = (rel / f.name).as_posix()
    return mapping


def remap_paths(log: dict, mapping: dict[str, str], stage: Path) -> int:
    """Rewrite every artifactLocation.uri in place from staged to original relative paths.

    Returns the number of uris that could not be mapped (left untouched).
    """
    unmapped = 0
    prefix = stage.as_posix().rstrip("/") + "/"

    def fix(uri: str) -> str | None:
        key = uri[7:] if uri.startswith("file://") else uri
        if key.startswith(prefix):
            key = key[len(prefix):]
        key = key[2:] if key.startswith("./") else key
        return mapping.get(key)

    def walk(o):
        nonlocal unmapped
        if isinstance(o, dict):
            al = o.get("artifactLocation")
            if isinstance(al, dict) and isinstance(al.get("uri"), str):
                new = fix(al["uri"])
                if new is None:
                    unmapped += 1
                else:
                    al["uri"] = new
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(log)
    return unmapped


class GosecAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SAST, languages=frozenset({"go"}),
                       license="Apache-2.0", restricted=False, offline_capable=True)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None) -> list[str] | None:
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    @staticmethod
    def detect_with(argv: list[str]) -> tuple[bool, str | None]:
        r = run_command([*argv, "-version"], timeout_s=15, max_output_bytes=4096)
        if r.returncode != 0:
            return False, None
        # gosec prints "Version: x.y.z" (or "dev" for source builds: version unknown -> None)
        return True, parse_version((r.stdout + r.stderr).decode("utf-8", "replace"))

    def detect(self) -> tuple[bool, str | None]:
        argv = self._argv()
        return self.detect_with(argv) if argv else (False, None)

    def applicable(self, t: Target) -> bool:
        if t.kind not in ("repo", "dir"):
            return False
        return not t.languages or "go" in t.languages

    def run(self, t: Target, cfg, *, timeout_s: int) -> ScannerResult:
        sw = Stopwatch()
        err = lambda st, d, v=None, f=None: result(ID, st, version=v, files=f, ms=sw.ms, detail=d)  # noqa: E731
        argv = self._argv(cfg)
        if not argv:
            return err(ScannerStatus.SKIPPED, "gosec not found (set GOSEC_BIN or `go install github.com/securego/gosec/v2/cmd/gosec@latest`)")
        _, version = self.detect_with(argv)
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        with tempfile.TemporaryDirectory(prefix="kscan-gosec-") as scratch:
            stage = Path(scratch) / "stage"
            stage.mkdir()
            mapping = stage_tree(path, stage)
            files = len(mapping)
            if files == 0:
                return err(ScannerStatus.EMPTY, "no analyzable .go files in target", version, 0)
            # -no-fail: findings must not produce a non-zero exit; ./... covers every staged dir.
            r = run_command([*argv, "-fmt=sarif", "-no-fail", "-quiet", "./..."],
                            timeout_s=timeout_s, cwd=str(stage))
            if r.timed_out:
                return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s", version, files)
            if r.error or r.returncode != 0:
                return err(ScannerStatus.ERROR, redact(r.error or f"exit {r.returncode}: " + r.stderr_tail()), version, files)
            if r.stdout_truncated:
                return err(ScannerStatus.ERROR, "SARIF output exceeded size cap", version, files)
            try:
                log = json.loads(r.stdout)
            except ValueError as e:
                return err(ScannerStatus.ERROR, f"invalid JSON from gosec: {e}", version, files)
            problems = sarif_mod.validate(log)
            if problems:
                return err(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(problems[:3]), version, files)
            unmapped = remap_paths(log, mapping, stage)
        detail = redact(r.stderr_tail(200).strip())
        if unmapped:
            detail = f"{unmapped} path(s) could not be mapped back; " + detail
        return result(ID, ScannerStatus.OK, version=version, files=files, sarif=log, ms=sw.ms, detail=detail)
