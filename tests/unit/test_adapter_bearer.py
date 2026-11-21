"""T-ADP for Bearer: resolution, statuses, golden SARIF via a stub binary."""
import json
import stat
from pathlib import Path

import pytest

from kaleidoscan.adapters.bearer import BearerAdapter, parse_version, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "bearer"
GOLDEN = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Bearer"}},
          "results": [{"ruleId": "python_lang_weak_hash_md5", "message": {"text": "weak hash"},
                       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                                           "region": {"startLine": 5}}}]}]}]}


def stub(tmp_path, body, version="bearer version 9.9.9, build abc"):
    p = tmp_path / "bearer"
    p.write_text(f"#!/bin/sh\n[ \"$1\" = version ] && {{ echo '{version}'; exit 0; }}\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def tgt(path, langs=("python",)):
    return Target(path=Path(path), kind="repo", languages=frozenset(langs))


def adapter(binp):
    return BearerAdapter(env={"BEARER_BIN": str(binp), "PATH": "", "SYNTH_SCANNERS": "/nonexistent"})


def test_parse_version_ignores_update_banner():
    banner = "You are running an outdated version of Bearer CLI, v2.1.3 is now available.\nbearer version 2.1.1, build x"
    assert parse_version(banner) == "2.1.1"
    assert parse_version("garbage") is None


def test_license_recorded_honestly():
    i = BearerAdapter.info
    assert i.license == "Elastic-2.0" and i.id == "bearer"


def test_resolve(tmp_path):
    assert resolve_binary(env={"BEARER_BIN": str(tmp_path / "nope"), "PATH": "/usr/bin"}) == (None, "explicit")
    exe = tmp_path / "s" / "bin" / "bearer"
    exe.parent.mkdir(parents=True); exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
    assert resolve_binary(env={"SYNTH_SCANNERS": str(tmp_path / "s"), "PATH": ""}) == ([str(exe)], "clone")
    assert resolve_binary(env={"SYNTH_SCANNERS": str(tmp_path / "x"), "PATH": ""}) == (None, "path")


def test_detect(tmp_path):
    assert adapter(stub(tmp_path, "exit 0")).detect() == (True, "9.9.9")
    assert BearerAdapter(env={"PATH": "", "SYNTH_SCANNERS": str(tmp_path)}).detect() == (False, None)


def test_applicable():
    a = BearerAdapter()
    assert a.applicable(tgt("/x", ("ruby",))) and a.applicable(tgt("/x", ()))
    assert not a.applicable(tgt("/x", ("rust",)))
    assert not a.applicable(Target(Path("/x"), "image", frozenset()))


def test_run_ok_golden_and_offline_flags(tmp_path):
    out = tmp_path / "g.json"; out.write_text(json.dumps(GOLDEN))
    log = tmp_path / "argv"
    r = adapter(stub(tmp_path, f'echo "$@" > {log}; cat {out}')).run(tgt(FX / "py"), None, timeout_s=30)
    assert (r.status, r.version, r.files_analyzed) == (ScannerStatus.OK, "9.9.9", 1)
    assert r.sarif == GOLDEN and r.scanner_id == "bearer"
    argv = log.read_text()
    assert "--disable-version-check" in argv and "--format sarif" in argv and "--exit-code 0" in argv


def test_clean_null_results_is_ok_not_empty(tmp_path):
    clean = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Bearer"}}, "results": None}]}
    out = tmp_path / "c.json"; out.write_text(json.dumps(clean))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX / "py"), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1 and r.sarif["runs"][0]["results"] == []


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


def test_missing_binary_target_pin(tmp_path):
    a = BearerAdapter(env={"PATH": "", "SYNTH_SCANNERS": str(tmp_path)})
    assert a.run(tgt(FX / "py"), None, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(stub(tmp_path, "exit 0"))
    assert b.run(tgt(tmp_path / "gone"), None, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(FX / "py"), {"version": "1.0.0"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_secret_in_stderr_is_redacted(tmp_path):
    r = adapter(stub(tmp_path, "echo 'token=ghp_" + "a" * 30 + "' >&2; exit 1")).run(tgt(FX / "py"), None, timeout_s=5)
    assert "ghp_" not in r.detail and r.status is ScannerStatus.ERROR


def test_option_injection_and_cwd_isolation(tmp_path, monkeypatch):
    d = tmp_path / "-rf"; d.mkdir(); (d / "a.py").write_text("x=1")
    log = tmp_path / "argv"
    b = stub(tmp_path, f'echo "$@" > {log}; mkdir -p .bearer; echo \'{json.dumps(GOLDEN)}\'')
    work = tmp_path / "cwd"; work.mkdir(); monkeypatch.chdir(work)
    # relative path starting with '-' lives under cwd
    (work / "-rf").mkdir(); (work / "-rf" / "a.py").write_text("x=1")
    r = adapter(b).run(tgt(Path("-rf")), None, timeout_s=5)
    assert r.status is ScannerStatus.OK
    assert log.read_text().split()[-1] == str((work / "-rf").resolve())
    assert not (work / ".bearer").exists()
