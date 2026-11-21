"""Real Semgrep binary (skipped with an explicit reason when not installed).

Uses a local rules file so it runs offline (the default registry config needs network).
"""
import shutil
from pathlib import Path

import pytest

from kaleidoscan.adapters.semgrep import SemgrepAdapter, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.integration
FX = Path(__file__).resolve().parent.parent / "fixtures" / "semgrep"


@pytest.mark.skipif(not resolve_binary()[0], reason="real semgrep not installed (set SEMGREP_BIN)")
def test_real_binary_local_rules_finds_command_injection(tmp_path):
    a = SemgrepAdapter()
    ok, ver = a.detect()
    assert ok and ver
    # Semgrep's default .semgrepignore skips `tests/`, so scan a copy outside the repo tree.
    shutil.copytree(FX / "py", tmp_path / "py")
    t = Target(path=tmp_path / "py", kind="repo", languages=frozenset({"python"}))
    r = a.run(t, {"config": str(FX / "rules")}, timeout_s=120)
    assert r.status is ScannerStatus.OK, r.detail
    assert r.files_analyzed == 1
    results = [x for run in r.sarif["runs"] for x in run["results"]]
    assert any(x["ruleId"].endswith("os-system-concat") for x in results)
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "app.py"


@pytest.mark.skipif(not resolve_binary()[0], reason="real semgrep not installed (set SEMGREP_BIN)")
def test_real_binary_bad_config_is_error_not_clean(tmp_path):
    t = Target(path=FX / "py", kind="repo", languages=frozenset({"python"}))
    r = SemgrepAdapter().run(t, {"config": str(tmp_path / "missing.yml")}, timeout_s=120)
    assert r.status in (ScannerStatus.ERROR, ScannerStatus.SKIPPED) and r.sarif is None
