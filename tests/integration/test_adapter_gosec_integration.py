"""Real gosec binary (skipped with an explicit reason when not installed)."""
from pathlib import Path

import pytest

from kaleidoscan.adapters.gosec import GosecAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "gosec" / "go"


@pytest.mark.skipif(not resolve_binary()[0], reason="real gosec not installed (set GOSEC_BIN)")
def test_real_binary_staged_scan_maps_paths_back():
    a = GosecAdapter()
    ok, _ = a.detect()
    assert ok
    r = a.run(Target(path=FX, kind="repo", languages=frozenset({"go"})), None, timeout_s=120)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 2
    found = {(x["ruleId"], x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
             for x in r.sarif["runs"][0]["results"]}
    # two files declaring different packages in different dirs; both must be found, original paths
    assert ("G401", "a.go") in found and ("G204", "sub/b.go") in found
