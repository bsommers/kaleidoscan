"""T-ADP for gosec: resolution, staging + path map-back, statuses via a stub binary."""
import json
import stat
from pathlib import Path

import pytest

from kaleidoscan.adapters.gosec import GosecAdapter, parse_version, resolve_binary, stage_tree
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "gosec" / "go"


def sarif(*uris):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gosec"}}, "results": [
        {"ruleId": "G401", "message": {"text": "m"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": u}, "region": {"startLine": 3}}}]} for u in uris]}]}


def stub(tmp_path, body):
    p = tmp_path / "gosec"
    p.write_text(f"#!/bin/sh\n[ \"$1\" = -version ] && {{ echo 'Version: 2.9.9'; exit 0; }}\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def tgt(path):
    return Target(path=Path(path), kind="repo", languages=frozenset({"go"}))


def adapter(binp):
    return GosecAdapter(env={"GOSEC_BIN": str(binp), "PATH": ""})


def test_parse_version():
    assert parse_version("Version: 2.21.4") == "2.21.4"
    assert parse_version("Version: dev") is None


def test_resolve(tmp_path):
    assert resolve_binary(env={"GOSEC_BIN": str(tmp_path / "no"), "PATH": "/usr/bin"}) == (None, "explicit")
    exe = tmp_path / "go" / "bin" / "gosec"
    exe.parent.mkdir(parents=True); exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
    assert resolve_binary(env={"HOME": str(tmp_path), "PATH": ""}) == ([str(exe)], "local")
    assert resolve_binary(env={"HOME": str(tmp_path / "x"), "PATH": "", "SYNTH_REPO": str(tmp_path / "y")}) == (None, "path")


def test_detect_and_applicable(tmp_path):
    assert adapter(stub(tmp_path, "exit 0")).detect() == (True, "2.9.9")
    a = GosecAdapter()
    assert a.applicable(tgt("/x")) and a.applicable(Target(Path("/x"), "repo", frozenset()))
    assert not a.applicable(Target(Path("/x"), "repo", frozenset({"python"})))


def test_stage_separates_mixed_packages(tmp_path):
    src = tmp_path / "src"; (src / "vendor").mkdir(parents=True); (src / "d").mkdir()
    (src / "a.go").write_text("package main\n"); (src / "b.go").write_text("package other\n")
    (src / "a_test.go").write_text("package main\n"); (src / "vendor" / "v.go").write_text("package v\n")
    (src / "d" / "c.go").write_text("package d\n"); (src / "d" / "e.go").write_text("package d\n")
    stage = tmp_path / "stage"; stage.mkdir()
    m = stage_tree(src, stage)
    assert m == {"main/a.go": "a.go", "other/b.go": "b.go", "d/c.go": "d/c.go", "d/e.go": "d/e.go"}
    assert all((stage / k).is_file() for k in m)


def test_run_stages_and_maps_back(tmp_path):
    # Stub echoes SARIF for whatever staged files it sees (relative to its cwd), plus records argv/cwd.
    log = tmp_path / "log"
    body = (f'echo "$@" > {log}; pwd >> {log}; '
            'python3 - <<"PY"\nimport json,os\n'
            'fs=sorted(os.path.relpath(os.path.join(d,f)) for d,_,n in os.walk(".") for f in n)\n'
            'print(json.dumps({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":['
            '{"ruleId":"G401","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":f},"region":{"startLine":9}}}]} for f in fs]}]}))\nPY')
    r = adapter(stub(tmp_path, body)).run(tgt(FX), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 2 and r.version == "2.9.9"
    uris = sorted(x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                  for x in r.sarif["runs"][0]["results"])
    assert uris == ["a.go", "sub/b.go"]  # staged paths (main/, other/ or dir-prefixed) mapped back
    argv, cwd = log.read_text().splitlines()
    assert argv == "-fmt=sarif -no-fail -quiet ./..."
    assert "kscan-gosec-" in cwd and str(FX) not in cwd


def test_remap_absolute_and_unmapped(tmp_path):
    # absolute staged uri + an unknown uri (left as-is, reported in detail)
    out = tmp_path / "s.json"
    body = (f'python3 - <<"PY"\nimport json,os\nd=json.load(open("{out}"))\n'
            'd["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]="file://"+os.getcwd()+"/a.go"\n'
            'print(json.dumps(d))\nPY')
    out.write_text(json.dumps(sarif("x", "zzz.go")))
    r = adapter(stub(tmp_path, body)).run(tgt(FX), None, timeout_s=30)
    uris = [x["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for x in r.sarif["runs"][0]["results"]]
    assert uris == ["a.go", "zzz.go"] and "1 path(s)" in r.detail


def test_empty_when_no_go_files(tmp_path):
    d = tmp_path / "docs"; d.mkdir(); (d / "a.txt").write_text("x"); (d / "only_test.go").write_text("package x\n")
    r = adapter(stub(tmp_path, "exit 9")).run(tgt(d), None, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0


def test_clean_over_files_is_ok(tmp_path):
    out = tmp_path / "c.json"; out.write_text(json.dumps(sarif()))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 2


@pytest.mark.parametrize("body,status", [
    ("echo boom >&2; exit 2", ScannerStatus.ERROR),
    ("echo not-json", ScannerStatus.ERROR),
    ("echo '{\"version\":\"1.0\",\"runs\":[]}'", ScannerStatus.ERROR),
    ("sleep 30", ScannerStatus.TIMEOUT),
])
def test_run_failures(tmp_path, body, status):
    r = adapter(stub(tmp_path, body)).run(tgt(FX), None, timeout_s=2)
    assert r.status is status and r.sarif is None


def test_missing_binary_target_pin(tmp_path):
    assert GosecAdapter(env={"PATH": "", "HOME": str(tmp_path), "SYNTH_REPO": str(tmp_path)}).run(
        tgt(FX), None, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(stub(tmp_path, "exit 0"))
    assert b.run(tgt(tmp_path / "gone"), None, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(FX), {"version": "1.0.0"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_secret_in_stderr_is_redacted(tmp_path):
    r = adapter(stub(tmp_path, "echo 'token=ghp_" + "a" * 30 + "' >&2; exit 1")).run(tgt(FX), None, timeout_s=5)
    assert "ghp_" not in r.detail and r.status is ScannerStatus.ERROR


def test_target_not_modified(tmp_path):
    before = sorted(p.relative_to(FX) for p in FX.rglob("*"))
    adapter(stub(tmp_path, f"echo '{json.dumps(sarif())}'")).run(tgt(FX), None, timeout_s=5)
    assert sorted(p.relative_to(FX) for p in FX.rglob("*")) == before
