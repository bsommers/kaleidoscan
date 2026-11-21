"""Real osv-scanner binary (skipped with an explicit reason when not installed; needs network)."""
from pathlib import Path

import pytest

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.osv_scanner import OsvScannerAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "osv-scanner"


@pytest.mark.skipif(not resolve_binary()[0], reason="real osv-scanner not installed (set OSV_SCANNER_BIN)")
def test_real_binary_flags_old_flask_or_skips_offline():
    a = OsvScannerAdapter()
    ok, ver = a.detect()
    assert ok and ver
    r = a.run(Target(path=FX / "repo", kind="repo", languages=frozenset()), None, timeout_s=120)
    if r.status is ScannerStatus.SKIPPED:
        pytest.skip(f"OSV API unreachable: {r.detail}")
    assert r.status is ScannerStatus.OK, r.detail
    assert sarif_mod.validate(r.sarif) == []
    assert any(x for run in r.sarif["runs"] for x in run["results"])
