"""T-ADP for CodeQL: license gate, per-language flow, statuses, scratch cleanup, via a stub binary."""
import json
import stat
from pathlib import Path

import pytest

from kaleidoscan.adapters.codeql import CodeqlAdapter, parse_version, resolve_binary
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "codeql"
OPT_IN = {"accept_license": True}


def golden(lang="python"):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": [
        {"ruleId": f"{lang}/command-line-injection", "message": {"text": "inj"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 6}}}]}]}]}


STUB = r"""#!/bin/sh
LOG="$KSCAN_STUB_LOG"
[ "$1" = version ] && { echo 9.9.9; exit 0; }
echo "$@" >> "$LOG"
pwd >> "$LOG.cwd"
if [ "$2" = create ]; then
  mkdir -p "$3"; echo "$3" >> "$LOG.dbs"; %(create)s
  exit 0
fi
if [ "$2" = analyze ]; then
  for a in "$@"; do case "$a" in --output=*) out="${a#--output=}";; esac; done
  %(analyze)s
fi
"""


def stub(tmp_path, create="", analyze=None):
    analyze = analyze or f"cat {tmp_path}/g.json > \"$out\""
    (tmp_path / "g.json").write_text(json.dumps(golden()))
    p = tmp_path / "codeql"
    p.write_text(STUB % {"create": create, "analyze": analyze})
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def adapter(tmp_path, binp):
    env = {"CODEQL_BIN": str(binp), "PATH": "", "SYNTH_SCANNERS": "/nonexistent",
           "KSCAN_STUB_LOG": str(tmp_path / "log")}
    import os
    os.environ["KSCAN_STUB_LOG"] = str(tmp_path / "log")  # stub is spawned with the full environ
    return CodeqlAdapter(env=env)


def tgt(path, langs=("python",)):
    return Target(path=Path(path), kind="repo", languages=frozenset(langs))


def test_restricted_license_info():
    assert CodeqlAdapter.info.restricted is True and CodeqlAdapter.info.id == "codeql"


def test_parse_version():
    assert parse_version("2.26.4\n") == "2.26.4" and parse_version("x") is None


def test_resolve(tmp_path):
    assert resolve_binary(env={"CODEQL_BIN": str(tmp_path / "n"), "PATH": "/usr/bin"}) == (None, "explicit")
    exe = tmp_path / "s" / "codeql" / "codeql"
    exe.parent.mkdir(parents=True); exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
    assert resolve_binary(env={"SYNTH_SCANNERS": str(tmp_path / "s"), "PATH": ""}) == ([str(exe)], "clone")
    assert resolve_binary(env={"CODEQL_HOME": str(exe.parent), "PATH": ""}) == ([str(exe)], "home")


def test_applicable():
    a = CodeqlAdapter()
    assert a.applicable(tgt("/x", ("c",))) and a.applicable(tgt("/x", ("csharp",)))
    assert not a.applicable(tgt("/x", ("ruby",)))


@pytest.mark.parametrize("cfg", [None, {}, {"accept_license": False}, {"accept_license": "yes"},
                                 {"accept_license": True, "enabled": False}])
def test_never_runs_without_acceptance(tmp_path, cfg):
    s = stub(tmp_path)
    r = adapter(tmp_path, s).run(tgt(FX / "py"), cfg, timeout_s=30)
    assert r.status is ScannerStatus.SKIPPED and "accept_license" in r.detail
    assert not (tmp_path / "log").exists()  # binary never invoked


def test_run_ok_flow_and_cleanup(tmp_path):
    s = stub(tmp_path)
    r = adapter(tmp_path, s).run(tgt(FX / "py"), OPT_IN, timeout_s=60)
    assert (r.status, r.version, r.files_analyzed) == (ScannerStatus.OK, "9.9.9", 1)
    assert r.sarif["runs"] == golden()["runs"]
    log = (tmp_path / "log").read_text()
    assert "database create" in log and "--language=python" in log and "python-security-extended.qls" in log
    assert "--format=sarif-latest" in log and "--build-mode=none" not in log  # interpreted: no build mode
    for db in (tmp_path / "log.dbs").read_text().split():
        assert not Path(db).exists()           # scratch databases deleted
    assert all(not c.startswith(str(FX)) for c in (tmp_path / "log.cwd").read_text().split())


def test_compiled_language_uses_build_mode_none(tmp_path):
    d = tmp_path / "j"; d.mkdir(); (d / "A.java").write_text("class A{}")
    s = stub(tmp_path)
    r = adapter(tmp_path, s).run(tgt(d, ("java",)), OPT_IN, timeout_s=60)
    assert r.status is ScannerStatus.OK
    assert "--build-mode=none" in (tmp_path / "log").read_text()


def test_multi_language_merges_runs(tmp_path):
    d = tmp_path / "m"; d.mkdir(); (d / "a.py").write_text("x"); (d / "b.go").write_text("package b")
    s = stub(tmp_path)
    r = adapter(tmp_path, s).run(tgt(d, ("python", "go")), OPT_IN, timeout_s=60)
    assert r.status is ScannerStatus.OK and len(r.sarif["runs"]) == 2 and r.files_analyzed == 2


def test_partial_failure_is_reported(tmp_path):
    d = tmp_path / "m"; d.mkdir(); (d / "a.py").write_text("x"); (d / "b.go").write_text("package b")
    s = stub(tmp_path, create='case "$3" in *db-go) echo bad >&2; exit 3;; esac')
    # create exits 0 after the case in STUB, so fail via analyze instead
    s = stub(tmp_path, analyze='case "$3" in *db-go) echo bad >&2; exit 3;; esac; cat %s/g.json > "$out"' % tmp_path)
    r = adapter(tmp_path, s).run(tgt(d, ("python", "go")), OPT_IN, timeout_s=60)
    assert r.status is ScannerStatus.OK and r.detail.startswith("PARTIAL") and len(r.sarif["runs"]) == 1


def test_empty_target(tmp_path):
    d = tmp_path / "docs"; d.mkdir(); (d / "a.txt").write_text("x")
    r = adapter(tmp_path, stub(tmp_path)).run(tgt(d), OPT_IN, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0


@pytest.mark.parametrize("analyze,status", [
    ('echo boom >&2; exit 2', ScannerStatus.ERROR),
    ('echo not-json > "$out"', ScannerStatus.ERROR),
    ('echo \'{"version":"1.0","runs":[]}\' > "$out"', ScannerStatus.ERROR),
    ('sleep 30', ScannerStatus.TIMEOUT),
])
def test_run_failures(tmp_path, analyze, status):
    r = adapter(tmp_path, stub(tmp_path, analyze=analyze)).run(tgt(FX / "py"), OPT_IN, timeout_s=3)
    assert r.status is status and r.sarif is None


def test_missing_binary_target_pin(tmp_path):
    assert CodeqlAdapter(env={"PATH": "", "SYNTH_SCANNERS": str(tmp_path)}).run(
        tgt(FX / "py"), OPT_IN, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(tmp_path, stub(tmp_path))
    assert b.run(tgt(tmp_path / "gone"), OPT_IN, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(FX / "py"), {**OPT_IN, "version": "1.0.0"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_secret_in_stderr_is_redacted(tmp_path):
    s = stub(tmp_path, analyze="echo 'token=ghp_" + "a" * 30 + "' >&2; exit 1")
    r = adapter(tmp_path, s).run(tgt(FX / "py"), OPT_IN, timeout_s=10)
    assert "ghp_" not in r.detail and r.status is ScannerStatus.ERROR
