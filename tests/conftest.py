import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def root() -> Path:
    return ROOT


@pytest.fixture
def run_cli():
    """Run `python -m kaleidoscan` with an optional PATH override; returns CompletedProcess."""

    def _run(*args: str, path: str | None = None, env: dict | None = None):
        e = dict(os.environ)
        if path is not None:
            e["PATH"] = path
        e.pop("FLOWSCOPE_BIN", None)
        e.update(env or {})
        return subprocess.run(
            [sys.executable, "-m", "kaleidoscan", *args],
            capture_output=True, text=True, env=e, timeout=60,
        )

    return _run


@pytest.fixture
def fake_bin(tmp_path):
    """Create a dir with a fake executable printing a version; returns (dir, make)."""

    def make(name: str, out: str = "1.2.3", code: int = 0) -> Path:
        p = tmp_path / name
        p.write_text(f"#!/bin/sh\necho '{out}'\nexit {code}\n")
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
        return tmp_path

    return make
