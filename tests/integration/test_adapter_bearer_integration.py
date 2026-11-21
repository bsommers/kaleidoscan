"""Real Bearer binary (skipped with an explicit reason when not installed)."""
from pathlib import Path

import pytest

from kaleidoscan.adapters.bearer import BearerAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "bearer"


@pytest.mark.skipif(not resolve_binary()[0], reason="real bearer not installed (set BEARER_BIN)")
def test_real_binary_finds_weak_hash():
    a = BearerAdapter()
    ok, ver = a.detect()
    assert ok and ver
    r = a.run(Target(FX / "py", "repo", frozenset({"python"})), None, timeout_s=120)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1
    assert any(x["ruleId"] == "python_lang_weak_hash_md5" for run in r.sarif["runs"] for x in run["results"])
