"""T-ADP for Bandit: JSON->SARIF conversion (golden), statuses via a stub binary."""
import json
import stat
from pathlib import Path

import pytest

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.bandit import BanditAdapter, bandit_json_to_sarif, parse_version, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "bandit"
ROOT = (FX / "py").resolve()


def golden_json():
    return (FX / "bandit_golden.json").read_text().replace("@ROOT@", str(ROOT))


def stub(tmp_path, body, version="bandit 9.9.9"):
    p = tmp_path / "bandit"
    p.write_text(f"#!/bin/sh\n[ \"$1\" = --version ] && {{ echo '{version}'; exit 0; }}\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def tgt(path, langs=("python",)):
    return Target(path=Path(path), kind="repo", languages=frozenset(langs))


def adapter(binp):
    return BanditAdapter(env={"BANDIT_BIN": str(binp), "PATH": ""})


def test_parse_version_info():
    assert parse_version("bandit 1.9.4\n  python version = 3.14") == "1.9.4"
    assert parse_version("nope") is None
    assert BanditAdapter.info.id == "bandit" and BanditAdapter.info.languages == frozenset({"python"})


def test_resolve(tmp_path):
    assert resolve_binary(env={"BANDIT_BIN": str(tmp_path / "no"), "PATH": "/usr/bin"}) == (None, "explicit")


def test_converter_golden():
    log = bandit_json_to_sarif(json.loads(golden_json()), ROOT, "9.9.9")
    assert sarif_mod.validate(log) == []
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "Bandit" and run["tool"]["driver"]["version"] == "9.9.9"
    res = run["results"][0]
    assert res["ruleId"] == "B605" and res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert res["locations"][0]["physicalLocation"]["region"] == {"startLine": 5, "endLine": 5, "startColumn": 5}
    assert res["properties"]["cwe"] == "CWE-78"
    assert "CWE-78" in run["tool"]["driver"]["rules"][0]["properties"]["tags"]


def test_converter_empty_and_levels():
    assert bandit_json_to_sarif({"results": []}, ROOT)["runs"][0]["results"] == []
    d = {"results": [{"test_id": "B1", "issue_severity": "LOW", "issue_text": "t", "filename": "/x/a.py", "line_number": 1},
                     {"test_id": "B2", "issue_severity": "MEDIUM", "issue_text": "t", "filename": "/x/a.py", "line_number": 2}]}
    assert [r["level"] for r in bandit_json_to_sarif(d, Path("/x"))["runs"][0]["results"]] == ["note", "warning"]


def test_run_ok_golden_exit1_means_findings(tmp_path):
    out = tmp_path / "g.json"; out.write_text(golden_json())
    r = adapter(stub(tmp_path, f"cat {out}; exit 1")).run(tgt(FX / "py"), None, timeout_s=30)
    assert (r.status, r.version, r.files_analyzed) == (ScannerStatus.OK, "9.9.9", 1)
    assert r.sarif["runs"][0]["results"][0]["ruleId"] == "B605"


def test_clean_is_ok_not_empty(tmp_path):
    out = tmp_path / "c.json"
    out.write_text(json.dumps({"errors": [], "metrics": {"_totals": {}, str(ROOT / "app.py"): {}}, "results": []}))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX / "py"), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1 and r.sarif["runs"][0]["results"] == []


def test_zero_files_from_metrics_is_empty(tmp_path):
    out = tmp_path / "c.json"
    out.write_text(json.dumps({"errors": [], "metrics": {"_totals": {}}, "results": []}))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX / "py"), None, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0


def test_empty_target(tmp_path):
    d = tmp_path / "docs"; d.mkdir(); (d / "a.txt").write_text("x")
    r = adapter(stub(tmp_path, "exit 9")).run(tgt(d), None, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0


@pytest.mark.parametrize("body,status", [
    ("echo boom >&2; exit 2", ScannerStatus.ERROR),
    ("echo not-json", ScannerStatus.ERROR),
    ("echo '{\"x\":1}'", ScannerStatus.ERROR),
    ("sleep 30", ScannerStatus.TIMEOUT),
])
def test_run_failures(tmp_path, body, status):
    r = adapter(stub(tmp_path, body)).run(tgt(FX / "py"), None, timeout_s=2)
    assert r.status is status and r.sarif is None


def test_missing_binary_target_and_pin(tmp_path):
    a = BanditAdapter(env={"PATH": "", "BANDIT_BIN": str(tmp_path / "none")})
    assert a.run(tgt(FX / "py"), None, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(stub(tmp_path, "exit 0"))
    assert b.run(tgt(tmp_path / "gone"), None, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(FX / "py"), {"version": "0.0.1"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_secret_in_stderr_is_redacted(tmp_path):
    r = adapter(stub(tmp_path, "echo 'token=ghp_" + "a" * 30 + "' >&2; exit 2")).run(tgt(FX / "py"), None, timeout_s=5)
    assert "ghp_" not in r.detail and r.status is ScannerStatus.ERROR


def test_argv_abs_target_and_scratch_cwd(tmp_path, monkeypatch):
    d = tmp_path / "-rf"; d.mkdir(); (d / "a.py").write_text("x=1")
    log = tmp_path / "argv"; cwdlog = tmp_path / "cwd"; out = tmp_path / "g.json"
    out.write_text(json.dumps({"metrics": {"_totals": {}, "a": {}}, "results": []}))
    work = tmp_path / "w"; work.mkdir(); monkeypatch.chdir(tmp_path)
    b = stub(tmp_path, f'echo "$@" > {log}; pwd > {cwdlog}; cat {out}')
    r = adapter(b).run(tgt(Path("-rf")), None, timeout_s=5)
    assert r.status is ScannerStatus.OK
    assert log.read_text().split()[-1] == str((tmp_path / "-rf").resolve())
    assert "json" in log.read_text() and Path(cwdlog.read_text().strip()) != tmp_path
