"""T-ADP for osv-scanner: stub binary, golden SARIF, exit-code mapping."""
import json
import stat
from pathlib import Path

import pytest

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.osv_scanner import OsvScannerAdapter, parse_version, resolve_binary
from kaleidoscan.types import ScannerKind, ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures" / "osv-scanner"
ROOT = (FX / "repo").resolve()


def golden():
    return (FX / "osv_golden.sarif").read_text().replace("@ROOT@", str(ROOT))


def stub(tmp_path, body):
    # real osv-scanner logs its version line via the logger; emulate on stderr
    p = tmp_path / "osv-scanner"
    p.write_text("#!/bin/sh\n[ \"$1\" = --version ] && { echo 'osv-scanner version: 9.9.9' >&2; exit 0; }\n" + body + "\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def tgt(path):
    return Target(path=Path(path), kind="repo", languages=frozenset())


def adapter(binp):
    return OsvScannerAdapter(env={"OSV_SCANNER_BIN": str(binp), "PATH": ""})


def test_info_version_resolve(tmp_path):
    i = OsvScannerAdapter.info
    assert (i.id, i.kind, i.license, i.offline_capable) == ("osv-scanner", ScannerKind.SCA, "Apache-2.0", False)
    assert parse_version("osv-scanner version: 2.7.1") == "2.7.1" and parse_version("x") is None
    assert resolve_binary(env={"OSV_SCANNER_BIN": str(tmp_path / "no"), "PATH": "/usr/bin"}) == (None, "explicit")


def test_exit1_vulns_found_is_ok(tmp_path):
    g = tmp_path / "g.sarif"; g.write_text(golden())
    r = adapter(stub(tmp_path, f"cat {g}; exit 1")).run(tgt(ROOT), None, timeout_s=30)
    assert (r.status, r.version, r.files_analyzed) == (ScannerStatus.OK, "9.9.9", 1)
    assert sarif_mod.validate(r.sarif) == []
    assert r.sarif["runs"][0]["results"][0]["ruleId"] == "GHSA-562c-5r94-xh97"


def test_exit0_clean_is_ok(tmp_path):
    g = tmp_path / "c.sarif"
    g.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv-scanner"}},
                                                           "artifacts": [{"location": {"uri": "x"}}], "results": []}]}))
    r = adapter(stub(tmp_path, f"cat {g}")).run(tgt(ROOT), None, timeout_s=30)
    assert r.status is ScannerStatus.OK and r.sarif["runs"][0]["results"] == []


def test_no_manifests_exit128_is_empty(tmp_path):
    r = adapter(stub(tmp_path, "echo 'No package sources found' >&2; exit 128")).run(tgt(ROOT), None, timeout_s=30)
    assert r.status is ScannerStatus.EMPTY and r.files_analyzed == 0 and "lockfile" in r.detail


@pytest.mark.parametrize("body", [
    "echo 'API query failed' >&2; exit 129",
    "echo 'dial tcp: lookup api.osv.dev: no such host' >&2; exit 127",
])
def test_offline_is_skipped_with_detail(tmp_path, body):
    r = adapter(stub(tmp_path, body)).run(tgt(ROOT), None, timeout_s=30)
    assert r.status is ScannerStatus.SKIPPED and "unreachable" in r.detail and r.sarif is None


@pytest.mark.parametrize("body,status", [
    ("echo boom >&2; exit 127", ScannerStatus.ERROR),
    ("echo 'bad config' >&2; exit 130", ScannerStatus.ERROR),
    ("echo not-json", ScannerStatus.ERROR),
    ("echo '{\"x\":1}'", ScannerStatus.ERROR),
    ("sleep 30", ScannerStatus.TIMEOUT),
])
def test_failures(tmp_path, body, status):
    r = adapter(stub(tmp_path, body)).run(tgt(ROOT), None, timeout_s=2)
    assert r.status is status and r.sarif is None


def test_missing_binary_target_pin(tmp_path):
    a = OsvScannerAdapter(env={"PATH": "", "OSV_SCANNER_BIN": str(tmp_path / "none")})
    assert a.run(tgt(ROOT), None, timeout_s=5).status is ScannerStatus.SKIPPED
    b = adapter(stub(tmp_path, "exit 0"))
    assert b.run(tgt(tmp_path / "gone"), None, timeout_s=5).status is ScannerStatus.ERROR
    assert b.run(tgt(ROOT), {"version": "0.0.1"}, timeout_s=5).status is ScannerStatus.SKIPPED


def test_argv_abs_target_scratch_cwd_offline_flag(tmp_path, monkeypatch):
    d = tmp_path / "-rf"; d.mkdir()
    argv = tmp_path / "argv"; cwd = tmp_path / "cwd"; g = tmp_path / "c.sarif"
    g.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": []}]}))
    monkeypatch.chdir(tmp_path)
    b = stub(tmp_path, f'echo "$@" > {argv}; pwd > {cwd}; cat {g}')
    r = adapter(b).run(tgt(Path("-rf")), {"offline": True}, timeout_s=5)
    assert r.status is ScannerStatus.OK
    toks = argv.read_text().split()
    assert toks[:2] == ["scan", "source"] and "-r" in toks and "--offline" in toks
    assert toks[toks.index("--format") + 1] == "sarif"
    assert toks[-1] == str((tmp_path / "-rf").resolve())
    assert Path(cwd.read_text().strip()) != tmp_path
