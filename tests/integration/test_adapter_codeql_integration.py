"""Real CodeQL binary: heavy, opt-in. Skips with an explicit reason if absent or not opted in."""
import os
from pathlib import Path

import pytest

from kaleidoscan.adapters.codeql import CodeqlAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "codeql"


def test_real_binary_without_acceptance_is_skipped():
    r = CodeqlAdapter().run(Target(FX / "py", "repo", frozenset({"python"})), None, timeout_s=10)
    assert r.status is ScannerStatus.SKIPPED


@pytest.mark.skipif(not resolve_binary()[0], reason="real codeql not installed (set CODEQL_BIN)")
@pytest.mark.skipif(os.environ.get("KSCAN_CODEQL_ACCEPT_LICENSE") != "1",
                    reason="CodeQL is license-restricted; set KSCAN_CODEQL_ACCEPT_LICENSE=1 to run the heavy real-binary test")
def test_real_binary_python_scan():
    a = CodeqlAdapter()
    ok, ver = a.detect()
    assert ok and ver
    r = a.run(Target(FX / "py", "repo", frozenset({"python"})), {"accept_license": True}, timeout_s=900)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1
    assert r.sarif["runs"]
