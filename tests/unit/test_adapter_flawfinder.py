"""T-ADP for flawfinder: resolution, statuses, golden SARIF via a stub binary."""
import json
import stat
from pathlib import Path

import pytest

from kaleidoscan.adapters.flawfinder import FlawfinderAdapter, parse_version, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "flawfinder" / "c"


def golden(uri):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Flawfinder"}}, "results": [
        {"ruleId": "FF1013", "message": {"text": "m"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "SRCROOT"}, "region": {"startLine": 5}}}]}]}]}


def stub(tmp_path, body):
    p = tmp_path / "flawfinder"
    p.write_text(f"#!/bin/sh\n[ \"$1\" = --version ] && {{ echo '2.0.99'; exit 0; }}\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def tgt(path, langs=("c",)):
    return Target(path=Path(path), kind="repo", languages=frozenset(langs))


def adapter(binp):
    return FlawfinderAdapter(env={"FLAWFINDER_BIN": str(binp), "PATH": ""})


def test_parse_version():
    assert parse_version("2.0.20") == "2.0.20" and parse_version("x") is None


def test_resolve(tmp_path):
    assert resolve_binary(env={"FLAWFINDER_BIN": str(tmp_path / "no"), "PATH": "/usr/bin"}) == (None, "explicit")
    exe = tmp_path / "s" / ".scanners" / "venv" / "bin" / "flawfinder"
    exe.parent.mkdir(parents=True); exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
    assert resolve_binary(env={"SYNTH_REPO": str(tmp_path / "s"), "PATH": ""}) == ([str(exe)], "local")
    assert resolve_binary(env={"SYNTH_REPO": str(tmp_path), "HOME": str(tmp_path), "PATH": ""}) == (None, "path")


def test_detect_applicable(tmp_path):
    assert adapter(stub(tmp_path, "exit 0")).detect() == (True, "2.0.99")
    a = FlawfinderAdapter()
    assert a.applicable(tgt("/x", ("cpp",))) and a.applicable(tgt("/x", ()))
    assert not a.applicable(tgt("/x", ("go",)))


def test_run_ok_relativizes_and_runs_in_scratch(tmp_path):
    log = tmp_path / "argv"
    body = f'echo "$@" > {log}; pwd >> {log}; echo \'{json.dumps(golden(str(FX.resolve() / "vuln.c")))}\'; exit 0'
    r = adapter(stub(tmp_path, body)).run(tgt(FX), None, timeout_s=30)
    assert (r.status, r.version, r.files_analyzed) == (ScannerStatus.OK, "2.0.99", 1)
    uri = r.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "vuln.c"
    argv, cwd = log.read_text().splitlines()
    assert argv == f"--sarif {FX.resolve()}" and "kscan-flawfinder-" in cwd


def test_clean_is_ok_empty_target_is_empty(tmp_path):
    clean = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Flawfinder"}}, "results": []}]}
    out = tmp_path / "c.json"; out.write_text(json.dumps(clean))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1
    d = tmp_path / "docs"; d.mkdir(); (d / "a.txt").write_text("x")
    e = adapter(stub(tmp_path, "exit 9")).run(tgt(d), None, timeout_s=30)
    assert e.status is ScannerStatus.EMPTY and e.files_analyzed == 0


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
    a = FlawfinderAdapter(env={"PATH": "", "HOME": str(tmp_path), "SYNTH_REPO": str(tmp_path)})
    assert a.run(tgt(FX), None, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(stub(tmp_path, "exit 0"))
    assert b.run(tgt(tmp_path / "gone"), None, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(FX), {"version": "1.0.0"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_secret_in_stderr_is_redacted(tmp_path):
    r = adapter(stub(tmp_path, "echo 'token=ghp_" + "a" * 30 + "' >&2; exit 1")).run(tgt(FX), None, timeout_s=5)
    assert "ghp_" not in r.detail and r.status is ScannerStatus.ERROR


def test_option_injection_path(tmp_path, monkeypatch):
    d = tmp_path / "-rf"; d.mkdir(); (d / "a.c").write_text("int x;")
    log = tmp_path / "argv"
    b = stub(tmp_path, f'echo "$@" > {log}; echo \'{json.dumps(golden("a.c"))}\'')
    monkeypatch.chdir(tmp_path)
    adapter(b).run(tgt(Path("-rf")), None, timeout_s=5)
    assert log.read_text().split()[-1] == str((tmp_path / "-rf").resolve())
