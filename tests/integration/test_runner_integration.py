"""Runner against real binaries on PATH (explicit SKIP if absent)."""
import shutil
import pytest
from kaleidoscan.runner import run_command, safe_path_arg

pytestmark = [pytest.mark.integration]


def test_real_echo_with_hostile_path(tmp_path):
    echo = shutil.which("echo")
    if not echo:
        pytest.skip("no echo binary on PATH")
    hostile = tmp_path / "a b; $(id) -x"
    hostile.mkdir()
    r = run_command([echo, safe_path_arg(hostile)], timeout_s=5)
    assert r.stdout.decode().strip() == str(hostile)


def test_real_sleep_timeout():
    sleep = shutil.which("sleep")
    if not sleep:
        pytest.skip("no sleep binary on PATH")
    assert run_command([sleep, "30"], timeout_s=1).timed_out
