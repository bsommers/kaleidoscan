"""T-ADP for gitleaks: stub binary, golden SARIF, mandatory redaction."""
import json
import stat
from pathlib import Path

import pytest

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.gitleaks import GitleaksAdapter, parse_version, resolve_binary, scrub_sarif
from kaleidoscan.types import ScannerKind, ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "gitleaks"
ROOT = (FX / "repo").resolve()
SECRET = "AKIA" + "IOSFODNN7EXAMPLE"


def golden(snippet="REDACTED"):
    return (FX / "gitleaks_golden.sarif").read_text().replace("@ROOT@", str(ROOT)).replace("@SNIPPET@", snippet)


def stub(tmp_path, body, version="v9.9.9"):
    p = tmp_path / "gitleaks"
    p.write_text(f"#!/bin/sh\n[ \"$1\" = version ] && {{ echo '{version}'; exit 0; }}\n{body}\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


# shell snippet: write $content to the value following --report-path
WRITE = ('while [ $# -gt 0 ]; do [ "$1" = --report-path ] && out="$2"; shift; done; cat {src} > "$out"; {tail}')


def writer(src, tail="exit 0"):
    return WRITE.format(src=src, tail=tail)


def tgt(path):
    return Target(path=Path(path), kind="repo", languages=frozenset())


def adapter(binp):
    return GitleaksAdapter(env={"GITLEAKS_BIN": str(binp), "PATH": ""})


def test_info_version_resolve(tmp_path):
    assert GitleaksAdapter.info.kind is ScannerKind.SECRETS and GitleaksAdapter.info.license == "MIT"
    assert GitleaksAdapter.info.id == "gitleaks"
    assert parse_version("v8.30.1\n") == "8.30.1" and parse_version("x") is None
    assert resolve_binary(env={"GITLEAKS_BIN": str(tmp_path / "no"), "PATH": "/usr/bin"}) == (None, "explicit")


def test_golden_ok_relative_uri_redacted(tmp_path):
    g = tmp_path / "g.sarif"; g.write_text(golden())
    r = adapter(stub(tmp_path, writer(g))).run(tgt(FX / "repo"), None, timeout_s=30)
    assert (r.status, r.version, r.files_analyzed) == (ScannerStatus.OK, "9.9.9", 1)
    assert sarif_mod.validate(r.sarif) == []
    res = r.sarif["runs"][0]["results"][0]
    assert res["ruleId"] == "aws-access-token"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "config.py" and loc["region"]["snippet"]["text"] == "[REDACTED]"


def test_planted_secret_never_in_output(tmp_path):
    """Even if the binary ignored --redact and leaked the secret everywhere, it must not surface."""
    leaky = json.loads(golden(SECRET))
    leaky["runs"][0]["results"][0]["message"]["text"] = f"found {SECRET} in config.py; password = hunter2hunter2"
    leaky["runs"][0]["results"][0]["partialFingerprints"]["commitMessage"] = f"oops {SECRET}"
    g = tmp_path / "leak.sarif"; g.write_text(json.dumps(leaky))
    r = adapter(stub(tmp_path, writer(g))).run(tgt(FX / "repo"), None, timeout_s=30)
    assert r.status is ScannerStatus.OK
    blob = json.dumps(r.sarif) + r.detail
    assert SECRET not in blob and "hunter2hunter2" not in blob


def test_planted_secret_in_stderr_not_in_detail(tmp_path):
    body = f"echo 'leak {SECRET} token=ghp_{'a' * 30}' >&2; exit 2"
    r = adapter(stub(tmp_path, body)).run(tgt(FX / "repo"), None, timeout_s=30)
    assert r.status is ScannerStatus.ERROR and SECRET not in r.detail and "ghp_" not in r.detail
    ok = adapter(stub(tmp_path, f"echo 'leak {SECRET}' >&2; " + writer(tmp_path / "x.sarif"))).run
    (tmp_path / "x.sarif").write_text(golden())
    assert SECRET not in ok(tgt(FX / "repo"), None, timeout_s=30).detail


def test_scrub_sarif_pure():
    log = json.loads(golden(SECRET))
    out = scrub_sarif(log)
    assert SECRET not in json.dumps(out) and SECRET in json.dumps(log)  # input untouched


def test_clean_is_ok(tmp_path):
    g = tmp_path / "c.sarif"
    g.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": []}]}))
    r = adapter(stub(tmp_path, writer(g))).run(tgt(FX / "repo"), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.sarif["runs"][0]["results"] == []


def test_empty_target(tmp_path):
    d = tmp_path / "e"; d.mkdir()
    r = adapter(stub(tmp_path, "exit 9")).run(tgt(d), None, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0


@pytest.mark.parametrize("body,status", [
    ("echo boom >&2; exit 1", ScannerStatus.ERROR),
    ("exit 0", ScannerStatus.ERROR),  # no report written
    ('while [ $# -gt 0 ]; do [ "$1" = --report-path ] && echo nope > "$2"; shift; done', ScannerStatus.ERROR),
    ("sleep 30", ScannerStatus.TIMEOUT),
])
def test_failures(tmp_path, body, status):
    r = adapter(stub(tmp_path, body)).run(tgt(FX / "repo"), None, timeout_s=2)
    assert r.status is status and r.sarif is None


def test_missing_binary_target_pin(tmp_path):
    a = GitleaksAdapter(env={"PATH": "", "GITLEAKS_BIN": str(tmp_path / "none")})
    assert a.run(tgt(FX / "repo"), None, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(stub(tmp_path, "exit 0"))
    assert b.run(tgt(tmp_path / "gone"), None, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(FX / "repo"), {"version": "0.0.1"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_argv_flags_abs_target_scratch_cwd(tmp_path, monkeypatch):
    d = tmp_path / "-rf"; d.mkdir(); (d / "a.txt").write_text("x")
    argv = tmp_path / "argv"; cwd = tmp_path / "cwd"; g = tmp_path / "c.sarif"
    g.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": []}]}))
    monkeypatch.chdir(tmp_path)
    b = stub(tmp_path, f'echo "$@" > {argv}; pwd > {cwd}; ' + writer(g))
    r = adapter(b).run(tgt(Path("-rf")), None, timeout_s=5)
    assert r.status is ScannerStatus.OK
    toks = argv.read_text().split()
    assert toks[toks.index("--source") + 1] == str((tmp_path / "-rf").resolve())
    for flag in ("--redact", "--no-git", "--report-format", "sarif", "--exit-code"):
        assert flag in toks
    assert Path(cwd.read_text().strip()) != tmp_path
