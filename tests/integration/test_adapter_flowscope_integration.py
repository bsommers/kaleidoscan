"""Real Flowscope binary (skipped with an explicit reason when not installed)."""
from pathlib import Path

import pytest

from kaleidoscan.adapters.flowscope import FlowscopeAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "flowscope"


def tgt(path):
    return Target(path=Path(path), kind="repo", languages=frozenset({"python"}))


@pytest.mark.skipif(not resolve_binary()[0], reason="real flowscope not installed")
def test_real_binary_finds_command_injection():
    a = FlowscopeAdapter()
    ok, ver = a.detect()
    assert ok and ver
    r = a.run(tgt(FX / "py"), None, timeout_s=60)
    assert r.status is ScannerStatus.OK
    assert any(x["ruleId"] == "CWE-078" for run in r.sarif["runs"] for x in run["results"])
