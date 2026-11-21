"""Real flawfinder binary (skipped with an explicit reason when not installed)."""
from pathlib import Path

import pytest

from kaleidoscan.adapters.flawfinder import FlawfinderAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "flawfinder" / "c"


@pytest.mark.skipif(not resolve_binary()[0], reason="real flawfinder not installed (set FLAWFINDER_BIN)")
def test_real_binary_finds_strcpy_with_exit_zero():
    a = FlawfinderAdapter()
    ok, ver = a.detect()
    assert ok and ver
    r = a.run(Target(path=FX, kind="repo", languages=frozenset({"c"})), None, timeout_s=60)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1
    res = r.sarif["runs"][0]["results"]
    assert res and all(x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "vuln.c" for x in res)
