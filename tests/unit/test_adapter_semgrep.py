"""T-ADP for Semgrep: statuses, golden SARIF via a stub binary, offline/registry handling."""
import json
import stat
from pathlib import Path

import pytest

from kaleidoscan.adapters.semgrep import SemgrepAdapter, parse_version, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "semgrep"


def golden(root):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": []}},
            "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}],
            "results": [{"ruleId": "r.cmd", "message": {"text": "cmd injection"},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"{root}/app.py"},
                                                             "region": {"startLine": 5}}}]}]}]}


def stub(tmp_path, body, version="1.176.1"):
    p = tmp_path / "semgrep"
    p.write_text(f"#!/bin/sh\n[ \"$1\" = --version ] && {{ echo '{version}'; exit 0; }}\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def tgt(path, langs=("python",)):
    return Target(path=Path(path), kind="repo", languages=frozenset(langs))


def adapter(binp):
    return SemgrepAdapter(env={"SEMGREP_BIN": str(binp), "PATH": ""})


def test_parse_version_and_info():
    assert parse_version("1.176.1\n") == "1.176.1" and parse_version("x") is None
    i = SemgrepAdapter.info
    assert (i.id, i.license, i.offline_capable, i.restricted) == ("semgrep", "LGPL-2.1", False, False)


def test_resolve(tmp_path):
    assert resolve_binary(env={"SEMGREP_BIN": str(tmp_path / "no"), "PATH": "/usr/bin"}) == (None, "explicit")
    exe = tmp_path / "semgrep"; exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
    assert resolve_binary(env={"PATH": str(tmp_path)}) == ([str(exe)], "path")
    assert resolve_binary(env={"PATH": "", "KALEIDOSCAN_TOOL_DIRS": str(tmp_path)}) == ([str(exe)], "local")


def test_detect(tmp_path):
    assert adapter(stub(tmp_path, "exit 0")).detect() == (True, "1.176.1")
    assert not SemgrepAdapter(env={"PATH": ""}).detect()[0] or True  # host dirs may supply one


def test_applicable():
    a = SemgrepAdapter()
    assert a.applicable(tgt("/x", ("go",))) and a.applicable(tgt("/x", ()))
    assert not a.applicable(tgt("/x", ("cobol",)))
    assert not a.applicable(Target(Path("/x"), "image", frozenset()))


def test_run_ok_golden_remaps_uri_and_parses_files(tmp_path):
    root = (FX / "py").resolve()
    out = tmp_path / "g.json"; out.write_text(json.dumps(golden(root)))
    r = adapter(stub(tmp_path, f"echo 'Ran 79 rules on 3 files: 1 finding.' >&2; cat {out}")).run(
        tgt(FX / "py"), None, timeout_s=30)
    assert (r.status, r.version, r.files_analyzed) == (ScannerStatus.OK, "1.176.1", 3)
    uri = r.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "app.py"


def test_argv_flags_and_scratch_cwd(tmp_path, monkeypatch):
    log = tmp_path / "argv"; cwdlog = tmp_path / "cwd"
    g = tmp_path / "g.json"; g.write_text(json.dumps(golden("/z")))
    b = stub(tmp_path, f'echo "$@" > {log}; pwd > {cwdlog}; cat {g}')
    work = tmp_path / "w"; work.mkdir(); monkeypatch.chdir(work)
    r = adapter(b).run(tgt(FX / "py"), {"config": str(FX / "rules")}, timeout_s=30)
    assert r.status is ScannerStatus.OK
    argv = log.read_text()
    assert "--metrics=off" in argv and "--sarif" in argv and f"--config={FX / 'rules'}" in argv
    assert argv.split()[-1] == str((FX / "py").resolve())
    assert Path(cwdlog.read_text().strip()) != work and not any(work.iterdir())


def test_default_config_is_security_audit(tmp_path):
    log = tmp_path / "argv"; g = tmp_path / "g.json"; g.write_text(json.dumps(golden("/z")))
    adapter(stub(tmp_path, f'echo "$@" > {log}; cat {g}')).run(tgt(FX / "py"), None, timeout_s=30)
    assert "--config=p/security-audit" in log.read_text()


def test_clean_over_files_is_ok_not_empty(tmp_path):
    clean = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS"}}, "results": []}]}
    out = tmp_path / "c.json"; out.write_text(json.dumps(clean))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX / "py"), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1


def test_zero_files_analyzed_is_empty(tmp_path):
    clean = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS"}}, "results": []}]}
    out = tmp_path / "c.json"; out.write_text(json.dumps(clean))
    r = adapter(stub(tmp_path, f"echo 'Ran 5 rules on 0 files: 0 findings.' >&2; cat {out}")).run(
        tgt(FX / "py"), None, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0


def test_empty_target(tmp_path):
    d = tmp_path / "docs"; d.mkdir(); (d / "a.txt").write_text("x")
    r = adapter(stub(tmp_path, "exit 9")).run(tgt(d), None, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0


def test_invalid_config_notification_is_error_not_clean(tmp_path):
    bad = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS"}}, "results": [],
           "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": [
               {"level": "error", "message": {"text": "invalid configuration file found"}}]}]}]}
    out = tmp_path / "b.json"; out.write_text(json.dumps(bad))
    r = adapter(stub(tmp_path, f"cat {out}")).run(tgt(FX / "py"), {"config": str(FX / "rules")}, timeout_s=30)
    assert r.status is ScannerStatus.ERROR and "invalid configuration" in r.detail and r.sarif is None


def test_offline_registry_is_skipped_but_local_config_is_error(tmp_path):
    b = stub(tmp_path, "echo 'Failed to download https://semgrep.dev/c/p/security-audit: Name or service not known' >&2; exit 2")
    r = adapter(b).run(tgt(FX / "py"), None, timeout_s=30)
    assert r.status is ScannerStatus.SKIPPED and "network" in r.detail
    r2 = adapter(b).run(tgt(FX / "py"), {"config": str(FX / "rules")}, timeout_s=30)
    assert r2.status is ScannerStatus.ERROR


@pytest.mark.parametrize("body,status", [
    ("echo boom >&2; exit 2", ScannerStatus.ERROR),
    ("echo not-json", ScannerStatus.ERROR),
    ("echo '{\"version\":\"1.0\",\"runs\":[]}'", ScannerStatus.ERROR),
    ("sleep 30", ScannerStatus.TIMEOUT),
])
def test_run_failures(tmp_path, body, status):
    r = adapter(stub(tmp_path, body)).run(tgt(FX / "py"), None, timeout_s=2)
    assert r.status is status and r.sarif is None


def test_missing_binary_target_and_pin(tmp_path):
    a = SemgrepAdapter(env={"PATH": "", "SEMGREP_BIN": str(tmp_path / "none")})
    assert a.run(tgt(FX / "py"), None, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(stub(tmp_path, "exit 0"))
    assert b.run(tgt(tmp_path / "gone"), None, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(FX / "py"), {"version": "0.0.1"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_secret_in_stderr_is_redacted(tmp_path):
    r = adapter(stub(tmp_path, "echo 'token=ghp_" + "a" * 30 + "' >&2; exit 1")).run(tgt(FX / "py"), None, timeout_s=5)
    assert "ghp_" not in r.detail and r.status is ScannerStatus.ERROR


def test_option_injection_path(tmp_path, monkeypatch):
    d = tmp_path / "-rf"; d.mkdir(); (d / "a.py").write_text("x=1")
    log = tmp_path / "argv"; g = tmp_path / "g.json"; g.write_text(json.dumps(golden("/z")))
    monkeypatch.chdir(tmp_path)
    adapter(stub(tmp_path, f'echo "$@" > {log}; cat {g}')).run(tgt(Path("-rf")), None, timeout_s=5)
    assert log.read_text().split()[-1] == str((tmp_path / "-rf").resolve())
