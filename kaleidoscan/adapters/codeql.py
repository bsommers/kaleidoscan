"""CodeQL adapter (restricted, opt-in): `database create --build-mode=none` + `database analyze`.

License: the CodeQL CLI/bundle is under the GitHub CodeQL Terms and Conditions -- free only for
open-source / academic research use, otherwise a GitHub Advanced Security licence is needed.
So `restricted=True`: the adapter NEVER runs unless the scanner config sets
`accept_license: true` (the operator's explicit acceptance); otherwise it returns SKIPPED with
an explanation. `enabled: false` in the config also skips.

Flow and suites are the proven ones from synth/scripts/run_scanners.sh (attribution): per
language `codeql database create <db> --language=L --source-root=<target> [--build-mode=none]
--overwrite --quiet` then `codeql database analyze <db> <suite> --format=sarif-latest
--output=<file> --threads=0 --quiet`. Python/JavaScript are interpreted so --build-mode=none is
omitted there (as in the proven script); cpp/java/csharp/go use none (no build needed).
Databases live in a scratch tempdir (cfg `scratch_dir` to relocate off tmpfs) and are deleted.
The whole run shares one `timeout_s` budget; heavy -- give it a generous value.
Binary resolution: `bin` cfg, $CODEQL_BIN, $CODEQL_HOME/codeql, synth clone
($SYNTH_SCANNERS or ~/src/synth/.scanners)/codeql/codeql, then PATH.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.base import (
    ScannerInfo, ScannerKind, ScannerResult, ScannerStatus, Stopwatch, Target, cfg_get,
    count_files, result,
)
from kaleidoscan.runner import redact, run_command, safe_path_arg

ID = "codeql"
# codeql language -> (source extensions, query suite, pass --build-mode=none)
LANGS = {
    "cpp": ((".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"), "cpp-security-and-quality.qls", True),
    "java": ((".java",), "java-security-and-quality.qls", True),
    "python": ((".py",), "python-security-extended.qls", False),
    "csharp": ((".cs",), "csharp-security-and-quality.qls", True),
    "go": ((".go",), "go-security-and-quality.qls", True),
    "javascript": ((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"), "javascript-security-and-quality.qls", False),
}
# kaleidoscan language names -> codeql language
ALIASES = {"c": "cpp", "cpp": "cpp", "java": "java", "python": "python", "csharp": "csharp",
           "go": "go", "javascript": "javascript", "typescript": "javascript"}
MAX_SARIF_BYTES = 256 * 1024 * 1024


def _is_exe(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


def resolve_binary(cfg=None, env=None) -> tuple[list[str] | None, str]:
    env = os.environ if env is None else env
    explicit = cfg_get(cfg, "bin") or env.get("CODEQL_BIN")
    if explicit:
        p = Path(explicit).expanduser()
        return ([str(p)], "explicit") if _is_exe(p) else (None, "explicit")
    if env.get("CODEQL_HOME"):
        p = Path(env["CODEQL_HOME"]).expanduser() / "codeql"
        if _is_exe(p):
            return [str(p)], "home"
    scanners = Path(env.get("SYNTH_SCANNERS") or "~/src/synth/.scanners").expanduser()
    p = scanners / "codeql" / "codeql"
    if _is_exe(p):
        return [str(p)], "clone"
    found = shutil.which("codeql", path=env.get("PATH"))
    return ([found], "path") if found else (None, "path")


def parse_version(text: str) -> str | None:
    """`codeql version --format=terse` prints just e.g. 2.26.4."""
    import re
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    return m.group(1) if m else None


def _languages_for(t: Target) -> list[str]:
    wanted = {ALIASES[l] for l in t.languages if l in ALIASES} if t.languages else set(LANGS)
    return [l for l in LANGS if l in wanted]


class CodeqlAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SAST, languages=frozenset(ALIASES),
                       license="restricted (GitHub CodeQL Terms)", restricted=True, offline_capable=True)

    def __init__(self, cfg=None, env=None):
        self._cfg, self._env = cfg, env
        self.channel: str | None = None

    def _argv(self, cfg=None) -> list[str] | None:
        argv, self.channel = resolve_binary(cfg if cfg is not None else self._cfg, self._env)
        return argv

    @staticmethod
    def detect_with(argv: list[str]) -> tuple[bool, str | None]:
        r = run_command([*argv, "version", "--format=terse"], timeout_s=60, max_output_bytes=4096)
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
        # License gate first: nothing is executed without explicit operator acceptance.
        if cfg_get(cfg, "enabled", True) is False or cfg_get(cfg, "accept_license") is not True:
            return err(ScannerStatus.SKIPPED,
                       "CodeQL is license-restricted (free for OSS/research only); opt in with "
                       "`accept_license: true` in the scanner config after reviewing the GitHub CodeQL terms")
        argv = self._argv(cfg)
        if not argv:
            return err(ScannerStatus.SKIPPED, "codeql not found (set CODEQL_BIN or CODEQL_HOME)")
        _, version = self.detect_with(argv)
        pin = cfg_get(cfg, "version")
        if pin and version != str(pin):
            return err(ScannerStatus.SKIPPED, f"version {version} != pinned {pin}", version)
        path = Path(t.path).resolve()
        if not path.exists():
            return err(ScannerStatus.ERROR, f"target does not exist: {path.name}", version)
        plan = [(l, n) for l in _languages_for(t) if (n := count_files(path, LANGS[l][0])) > 0]
        files = sum(n for _, n in plan)
        if not plan:
            return err(ScannerStatus.EMPTY, "no CodeQL-supported (C/C++/Java/Python/C#/Go/JS/TS) files in target",
                       version, 0)
        deadline = time.monotonic() + timeout_s
        runs: list[dict] = []
        failures: list[str] = []
        scratch_root = cfg_get(cfg, "scratch_dir")
        # cwd and databases both live in a scratch dir that is removed afterwards.
        with tempfile.TemporaryDirectory(prefix="kscan-codeql-", dir=scratch_root) as scratch:
            for lang, _n in plan:
                _exts, suite, no_build = LANGS[lang]
                db = os.path.join(scratch, f"db-{lang}")
                out = os.path.join(scratch, f"{lang}.sarif")
                create = [*argv, "database", "create", db, f"--language={lang}",
                          f"--source-root={safe_path_arg(path)}"]
                if no_build:
                    create.append("--build-mode=none")
                create += ["--overwrite", "--quiet"]
                analyze = [*argv, "database", "analyze", db, suite, "--format=sarif-latest",
                           f"--output={out}", "--threads=0", "--quiet"]
                for step, cmd in (("create", create), ("analyze", analyze)):
                    left = deadline - time.monotonic()
                    if left <= 1:
                        return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s during {lang} {step}", version, files)
                    r = run_command(cmd, timeout_s=left, cwd=scratch)
                    if r.timed_out:
                        return err(ScannerStatus.TIMEOUT, f"exceeded {timeout_s}s during {lang} {step}", version, files)
                    if r.error or r.returncode != 0:
                        failures.append(f"{lang} {step}: " + redact(r.error or f"exit {r.returncode}: " + r.stderr_tail(150)))
                        break
                else:
                    try:
                        if os.path.getsize(out) > MAX_SARIF_BYTES:
                            failures.append(f"{lang}: SARIF exceeded size cap")
                            continue
                        with open(out, "rb") as fh:
                            log = json.load(fh)
                    except (OSError, ValueError) as e:
                        failures.append(f"{lang}: unreadable SARIF: {type(e).__name__}")
                        continue
                    problems = sarif_mod.validate(log)
                    if problems:
                        failures.append(f"{lang}: invalid SARIF: " + "; ".join(problems[:2]))
                        continue
                    runs.extend(log["runs"])
        if not runs:
            return err(ScannerStatus.ERROR, "; ".join(failures) or "no SARIF produced", version, files)
        merged = {"version": "2.1.0", "runs": runs}
        detail = ("PARTIAL, failed: " + "; ".join(failures)) if failures else f"languages: {', '.join(l for l, _ in plan)}"
        return result(ID, ScannerStatus.OK, version=version, files=files, sarif=merged, ms=sw.ms, detail=detail)
