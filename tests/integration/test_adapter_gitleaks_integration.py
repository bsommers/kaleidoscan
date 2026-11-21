"""Real gitleaks binary (skipped with an explicit reason when not installed)."""
import json
from pathlib import Path

import pytest

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.gitleaks import GitleaksAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "gitleaks"
SECRET = "AKIA" + "IOSFODNN7EXAMPLE"


@pytest.mark.skipif(not resolve_binary()[0], reason="real gitleaks not installed (set GITLEAKS_BIN)")
def test_real_binary_finds_planted_secret_redacted():
    a = GitleaksAdapter()
    ok, ver = a.detect()
    assert ok and ver
    r = a.run(Target(path=FX / "repo", kind="repo", languages=frozenset()), None, timeout_s=60)
    assert r.status is ScannerStatus.OK, r.detail
    assert sarif_mod.validate(r.sarif) == []
    results = [x for run in r.sarif["runs"] for x in run["results"]]
    assert results and results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "config.py"
    assert SECRET not in json.dumps(r.sarif) + r.detail
