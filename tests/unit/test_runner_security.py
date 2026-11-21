"""T-SEC (subprocess): argv-only execution, output caps, kill semantics."""
import ast
import os
import signal
import sys
import time
from pathlib import Path

import pytest

from kaleidoscan import runner
from kaleidoscan.runner import run_command, redact, safe_path_arg

pytestmark = [pytest.mark.security]
PY = sys.executable


def test_no_shell_true_anywhere_in_package():
    bad = []
    pkg = Path(runner.__file__).parent
    for f in pkg.rglob("*.py"):
        for n in ast.walk(ast.parse(f.read_text())):
            if isinstance(n, ast.keyword) and n.arg == "shell" and not (
                isinstance(n.value, ast.Constant) and n.value.value is False
            ):
                bad.append(f"{f}:{n.value.lineno}")
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                if n.func.attr in {"system", "popen"} and getattr(n.func.value, "id", "") == "os":
                    bad.append(f"{f}:{n.lineno} os.{n.func.attr}")
    assert not bad, bad


@pytest.mark.parametrize("bad", ["echo hi", b"echo", None, 5])
def test_non_list_argv_rejected(bad):
    with pytest.raises(TypeError):
        run_command(bad, timeout_s=5)


def test_empty_argv_and_non_str_items_and_nul_rejected():
    with pytest.raises(ValueError):
        run_command([], timeout_s=5)
    with pytest.raises(TypeError):
        run_command([PY, 5], timeout_s=5)
    with pytest.raises(ValueError):
        run_command([PY, "a\x00b"], timeout_s=5)


@pytest.mark.parametrize("arg", [
    "; rm -rf /", "$(touch PWNED)", "`touch PWNED`", "a b  c", "x && touch PWNED",
    "| cat", "'quote\"", "*", "-rf", "--version", "$HOME", "\nnewline",
])
def test_shell_metacharacters_are_literal(tmp_path, arg):
    r = run_command([PY, "-c", "import sys;sys.stdout.write(sys.argv[1])", arg],
                    cwd=tmp_path, timeout_s=10)
    assert r.returncode == 0 and r.stdout.decode() == arg
    assert not (tmp_path / "PWNED").exists()


def test_safe_path_arg_neutralises_leading_dash():
    assert safe_path_arg("-rf") == "./-rf"
    assert safe_path_arg("/abs/-x") == "/abs/-x"
    assert safe_path_arg(Path("ok")) == "ok"


def test_missing_binary_is_result_not_crash():
    r = run_command(["definitely-not-a-binary-xyz"], timeout_s=5)
    assert r.returncode is None and r.error and not r.timed_out


def test_huge_output_capped_and_child_not_blocked():
    code = "import sys\nfor _ in range(2000): sys.stdout.write('A'*10000)\nsys.stderr.write('E'*500000)"
    r = run_command([PY, "-c", code], timeout_s=20, max_output_bytes=4096)
    assert r.returncode == 0
    assert len(r.stdout) <= 4096 and len(r.stderr) <= 4096
    assert r.stdout_truncated and r.stderr_truncated


def test_small_output_not_flagged_truncated():
    r = run_command([PY, "-c", "print('hi')"], timeout_s=10, max_output_bytes=4096)
    assert r.stdout == b"hi\n" and not r.stdout_truncated


def test_hung_child_killed_on_timeout():
    t = time.monotonic()
    r = run_command([PY, "-c", "import time;time.sleep(60)"], timeout_s=1)
    assert r.timed_out and time.monotonic() - t < 10


def test_sigterm_ignoring_child_is_sigkilled():
    code = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('up',flush=True);time.sleep(60)"
    t = time.monotonic()
    r = run_command([PY, "-c", code], timeout_s=1, kill_grace_s=0.5)
    assert r.timed_out and time.monotonic() - t < 10


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # zombie counts as dead
        return "Z" not in Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False


def _wait_dead(pid, secs=5):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


GRANDCHILD = (
    "import subprocess,sys,time;"
    "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']);"
    "print(p.pid,flush=True);{tail}"
)


def test_orphan_grandchild_killed_on_timeout():
    r = run_command([PY, "-c", GRANDCHILD.format(tail="time.sleep(120)")], timeout_s=1)
    gpid = int(r.stdout.split()[0])
    assert r.timed_out and _wait_dead(gpid)


def test_orphan_grandchild_killed_after_normal_exit():
    # parent exits 0 immediately but leaves a grandchild holding the pipes
    r = run_command([PY, "-c", GRANDCHILD.format(tail="")], timeout_s=10)
    gpid = int(r.stdout.split()[0])
    assert r.returncode == 0 and _wait_dead(gpid)


def test_redact_secrets():
    s = "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 AKIAABCDEFGHIJKLMNOP password: hunter2 ok"
    out = redact(s)
    assert "ghp_abcdef" not in out and "AKIAABCDEFGHIJKLMNOP" not in out and "hunter2" not in out
    assert "ok" in out


def test_stderr_tail_is_bounded_and_redacted():
    r = run_command([PY, "-c", "import sys;sys.stderr.write('x'*10000+' api_key=SECRET123')"], timeout_s=10)
    tail = r.stderr_tail(200)
    assert len(tail) <= 220 and "SECRET123" not in tail
