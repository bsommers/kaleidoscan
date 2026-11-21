"""Real Bandit binary (skipped with an explicit reason when not installed)."""
from pathlib import Path

import pytest

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.bandit import BanditAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "bandit"


@pytest.mark.skipif(not resolve_binary()[0], reason="real bandit not installed (set BANDIT_BIN)")
def test_real_binary_finds_shell_injection():
    a = BanditAdapter()
    ok, ver = a.detect()
    assert ok and ver
    r = a.run(Target(path=FX / "py", kind="repo", languages=frozenset({"python"})), None, timeout_s=60)
    assert r.status is ScannerStatus.OK, r.detail
    assert r.files_analyzed == 1 and sarif_mod.validate(r.sarif) == []
    results = [x for run in r.sarif["runs"] for x in run["results"]]
    assert any(x["ruleId"] == "B605" and x["properties"]["cwe"] == "CWE-78" for x in results)
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
