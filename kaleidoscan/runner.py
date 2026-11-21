"""Runner engine: safe subprocess execution, parallel pool, atomic run-dir writes.

Trust boundary: every command is an argv *list* executed without a shell. Output is
bounded, the whole process group is killed on timeout (and orphans reaped after normal
exit), and results are written atomically. Adapters (contract C1) are consumed by duck
typing; no import of unmerged modules is required.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

DEFAULT_MAX_OUTPUT = 64 * 1024 * 1024
_READ_CHUNK = 65536

# ---- redaction ---------------------------------------------------------------

_REDACTIONS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
]
_KV = re.compile(
    r"(?i)\b([\w.-]*(?:password|passwd|secret|token|api[_-]?key|apikey|auth)[\w.-]*)(\s*[=:]\s*)(\S+)"
)


def redact(text: str) -> str:
    for rx in _REDACTIONS:
        text = rx.sub("[REDACTED]", text)
    return _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)


def safe_path_arg(p: str | os.PathLike) -> str:
    """Make a path safe to pass as a positional argv item (no option injection)."""
    s = os.fspath(p)
    return "./" + s if s.startswith("-") else s


# ---- subprocess executor -----------------------------------------------------

@dataclass
class CommandResult:
    argv: list[str]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    error: str | None = None

    def stderr_tail(self, n: int = 500) -> str:
        """Bounded, redacted tail of stderr suitable for ScannerResult.detail."""
        txt = self.stderr.decode("utf-8", "replace")
        return redact(txt)[-n:]


def _validate_argv(argv: Any) -> list[str]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, (list, tuple)):
        raise TypeError("argv must be a list of str (shell strings are never accepted)")
    if not argv:
        raise ValueError("argv is empty")
    out = []
    for a in argv:
        a = os.fspath(a) if isinstance(a, os.PathLike) else a
        if not isinstance(a, str):
            raise TypeError(f"argv items must be str, got {type(a).__name__}")
        if "\x00" in a:
            raise ValueError("NUL byte in argv")
        out.append(a)
    return out


def _killpg(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def _drain(stream, cap: int, buf: bytearray, flag: list) -> None:
    """Read to EOF, retaining at most `cap` bytes; keep draining so the child never blocks."""
    try:
        while True:
            chunk = stream.read(_READ_CHUNK)
            if not chunk:
                return
            room = cap - len(buf)
            if room > 0:
                buf += chunk[:room]
            if len(chunk) > room:
                flag[0] = True
    except (OSError, ValueError):
        return


def run_command(
    argv: Sequence[str],
    *,
    timeout_s: float,
    cwd: str | os.PathLike | None = None,
    env: dict[str, str] | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT,
    kill_grace_s: float = 2.0,
) -> CommandResult:
    args = _validate_argv(argv)
    if max_output_bytes < 0 or timeout_s <= 0:
        raise ValueError("timeout_s must be > 0 and max_output_bytes >= 0")
    start = time.monotonic()

    def done(rc, so, se, to, f1, f2, err=None):
        return CommandResult(args, rc, bytes(so), bytes(se), to, f1, f2,
                             int((time.monotonic() - start) * 1000), err)

    try:
        proc = subprocess.Popen(
            args, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd, env=env if env is not None else os.environ.copy(),
            start_new_session=True, close_fds=True,
        )
    except (OSError, ValueError) as e:
        return done(None, b"", b"", False, False, False, f"{type(e).__name__}: {e}")

    pgid = proc.pid
    bufs = (bytearray(), bytearray())
    flags = ([False], [False])
    readers = [
        threading.Thread(target=_drain, args=(s, max_output_bytes, b, f), daemon=True)
        for s, b, f in ((proc.stdout, bufs[0], flags[0]), (proc.stderr, bufs[1], flags[1]))
    ]
    for t in readers:
        t.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _killpg(pgid, signal.SIGTERM)
        try:
            proc.wait(timeout=kill_grace_s)
        except subprocess.TimeoutExpired:
            pass
    finally:
        # Always take down the group: reaps orphaned grandchildren and SIGKILLs stragglers.
        _killpg(pgid, signal.SIGKILL)
        try:
            proc.wait(timeout=kill_grace_s + 5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            pass
        for t in readers:
            t.join(timeout=5)
        for s in (proc.stdout, proc.stderr):
            try:
                s.close()
            except OSError:
                pass
    return done(None if timed_out else proc.returncode, bufs[0], bufs[1], timed_out,
                flags[0][0], flags[1][0])


# ---- parallel pool -----------------------------------------------------------

class _Fallback:
    """Minimal ScannerResult stand-in when the real type is unavailable."""

    def __init__(self, scanner_id, status, detail):
        self.scanner_id, self.status, self.detail = scanner_id, status, detail
        self.version = self.files_analyzed = self.sarif = None
        self.duration_ms = 0


def _make_result(scanner_id: str, status: str, detail: str, duration_ms: int = 0):
    try:
        from kaleidoscan.types import ScannerResult, ScannerStatus

        return ScannerResult(scanner_id=scanner_id, status=ScannerStatus(status), version=None,
                             files_analyzed=None, sarif=None, duration_ms=duration_ms, detail=detail)
    except Exception:
        r = _Fallback(scanner_id, status, detail)
        r.duration_ms = duration_ms
        return r


def run_parallel(adapters: Sequence[Any], target: Any, cfg: Any, *, timeout_s: int,
                 max_parallel: int = 4, grace_s: float = 5.0, cfg_for=None) -> list[Any]:
    """Run adapters concurrently (<= max_parallel); results are returned in input order.

    A hung or crashing adapter yields a TIMEOUT/ERROR result and never blocks the others.
    Worker threads are daemons, so an unkillable in-process hang cannot stall exit.
    """
    if max_parallel < 1:
        raise ValueError("max_parallel must be >= 1")
    n = len(adapters)
    results: list[Any] = [None] * n
    sem = threading.Semaphore(max_parallel)
    deadlines: list[float | None] = [None] * n
    finished = [threading.Event() for _ in range(n)]
    lock = threading.Lock()

    def work(i: int) -> None:
        a = adapters[i]
        sid = a.info.id
        with sem:
            t0 = time.monotonic()
            with lock:
                deadlines[i] = t0 + timeout_s + grace_s
            try:
                r = a.run(target, cfg_for(a) if cfg_for else cfg, timeout_s=timeout_s)
            except Exception as e:  # adapter bugs must not take down the run
                r = _make_result(sid, "error", redact(f"{type(e).__name__}: {e}")[-500:],
                                 int((time.monotonic() - t0) * 1000))
            with lock:
                if results[i] is None:
                    results[i] = r
        finished[i].set()

    for i in range(n):
        threading.Thread(target=work, args=(i,), daemon=True, name=f"kscan-{i}").start()

    for i in range(n):
        while not finished[i].wait(0.05):
            with lock:
                dl = deadlines[i]
                if dl is not None and time.monotonic() > dl and results[i] is None:
                    results[i] = _make_result(
                        adapters[i].info.id, "timeout", f"exceeded {timeout_s}s", int(timeout_s * 1000))
                    break
    return results


# ---- run dir + atomic writes -------------------------------------------------

_RUN_ID_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def create_run_dir(out_dir: str | os.PathLike, run_id: str | None = None) -> tuple[str, Path]:
    """Create a fresh `<out_dir>/runs/<run_id>/` (exclusive; never reuses an existing run)."""
    rid = run_id if run_id is not None else str(uuid.uuid4())
    if not _RUN_ID_OK.match(rid) or ".." in rid:
        raise ValueError(f"invalid run_id: {rid!r}")
    runs = Path(out_dir) / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    p = runs / rid
    p.mkdir()  # FileExistsError if taken: refuse rather than merge
    return rid, p


def atomic_write(path: str | os.PathLike, data: bytes | str) -> None:
    """Write via temp file in the same dir + fsync + os.replace; readers never see a partial file."""
    path = Path(path)
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # replaces a symlink at `path` itself, never its target
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
