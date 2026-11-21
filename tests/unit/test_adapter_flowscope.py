"""T-ADP for Flowscope: resolution, statuses, golden SARIF via a stub binary, real-binary smoke."""
import json
import os
import stat
from pathlib import Path

import pytest

from kaleidoscan import adapters
from kaleidoscan.adapters.flowscope import FlowscopeAdapter, parse_version, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "flowscope"
GOLDEN = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "flowscope", "version": "9.9.9"}},
          "results": [{"ruleId": "CWE-078", "message": {"text": "cmd injection"},
                       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                                           "region": {"startLine": 5}}}]}]}]}


def stub(tmp_path, body, version="flowscope 9.9.9"):
    p = tmp_path / "flowscope"
    p.write_text(f"#!/bin/sh\n[ \"$1\" = --version ] && {{ echo '{version}'; exit 0; }}\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def tgt(path, langs=("python",)):
    return Target(path=Path(path), kind="repo", languages=frozenset(langs))


def adapter(binp):
    return FlowscopeAdapter(env={"FLOWSCOPE_BIN": str(binp), "PATH": ""})


def test_parse_version():
    assert parse_version("flowscope 0.4.5") == "0.4.5"
    assert parse_version("garbage") is None


def test_registry_has_flowscope():
    assert isinstance(adapters.get("flowscope"), FlowscopeAdapter)
    with pytest.raises(KeyError):
        adapters.get("nope")


def test_resolve_explicit_missing_does_not_fall_back(tmp_path):
    assert resolve_binary(env={"FLOWSCOPE_BIN": str(tmp_path / "nope"), "PATH": "/usr/bin"}) == (None, "explicit")


def test_resolve_clone_and_path(tmp_path):
    exe = tmp_path / "repo" / "target" / "release" / "flowscope"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
    assert resolve_binary(env={"FLOWSCOPE_REPO": str(tmp_path / "repo"), "PATH": ""}) == ([str(exe)], "clone")
    assert resolve_binary(env={"FLOWSCOPE_REPO": str(tmp_path / "x"), "PATH": ""}) == (None, "path")


def test_detect(tmp_path):
    assert adapter(stub(tmp_path, "exit 0")).detect() == (True, "9.9.9")
    assert FlowscopeAdapter(env={"PATH": "", "FLOWSCOPE_REPO": str(tmp_path)}).detect() == (False, None)


def test_applicable():
    a = FlowscopeAdapter()
    assert a.applicable(tgt("/x", ("python",)))
    assert a.applicable(tgt("/x", ()))            # languages unknown: let it try
    assert not a.applicable(tgt("/x", ("rust",)))  # flowscope#20
    assert not a.applicable(Target(Path("/x"), "image", frozenset()))


def test_run_ok_golden(tmp_path):
    out = tmp_path / "g.json"; out.write_text(json.dumps(GOLDEN))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX / "py"), None, timeout_s=30)
    assert (r.status, r.version, r.files_analyzed) == (ScannerStatus.OK, "9.9.9", 1)
    assert r.sarif == GOLDEN and r.scanner_id == "flowscope"


def test_run_clean_over_files_is_ok_not_empty(tmp_path):
    clean = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "flowscope"}}, "results": []}]}
    out = tmp_path / "c.json"; out.write_text(json.dumps(clean))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX / "py"), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1


def test_run_empty_target(tmp_path):
    d = tmp_path / "docs"; d.mkdir(); (d / "a.txt").write_text("x")
    r = adapter(stub(tmp_path, "exit 9")).run(tgt(d), None, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0


@pytest.mark.parametrize("body,status", [
    ("echo boom >&2; exit 2", ScannerStatus.ERROR),
    ("echo not-json", ScannerStatus.ERROR),
    ("echo '{\"version\":\"1.0\",\"runs\":[]}'", ScannerStatus.ERROR),
    ("sleep 30", ScannerStatus.TIMEOUT),
])
def test_run_failures(tmp_path, body, status):
    r = adapter(stub(tmp_path, body)).run(tgt(FX / "py"), None, timeout_s=2)
    assert r.status is status and r.sarif is None


def test_run_missing_binary_and_target_and_pin(tmp_path):
    a = FlowscopeAdapter(env={"PATH": "", "FLOWSCOPE_REPO": str(tmp_path)})
    assert a.run(tgt(FX / "py"), None, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(stub(tmp_path, "exit 0"))
    assert b.run(tgt(tmp_path / "gone"), None, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(FX / "py"), {"version": "1.0.0"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_secret_in_stderr_is_redacted(tmp_path):
    r = adapter(stub(tmp_path, "echo 'token=ghp_" + "a" * 30 + "' >&2; exit 1")).run(tgt(FX / "py"), None, timeout_s=5)
    assert "ghp_" not in r.detail and r.status is ScannerStatus.ERROR


def test_option_injection_path(tmp_path, monkeypatch):
    d = tmp_path / "-rf"; d.mkdir(); (d / "a.py").write_text("x=1")
    log = tmp_path / "argv"
    b = stub(tmp_path, f'echo "$@" > {log}; echo \'{json.dumps(GOLDEN)}\'')
    monkeypatch.chdir(tmp_path)
    adapter(b).run(tgt(Path("-rf")), None, timeout_s=5)
    assert log.read_text().split()[-1] == str((tmp_path / "-rf").resolve())


def test_scan_does_not_write_into_cwd_or_target(tmp_path, monkeypatch):
    work = tmp_path / "cwd"; work.mkdir(); monkeypatch.chdir(work)
    b = stub(tmp_path, f"mkdir -p .flowscope; echo '{json.dumps(GOLDEN)}'")
    r = adapter(b).run(tgt(FX / "py"), None, timeout_s=5)
    assert r.status is ScannerStatus.OK
    assert not (work / ".flowscope").exists() and not (FX / "py" / ".flowscope").exists()

