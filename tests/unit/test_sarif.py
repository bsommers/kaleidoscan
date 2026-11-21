import copy
import json
from pathlib import Path

import pytest

from kaleidoscan import sarif as S
from kaleidoscan.redact import redact

pytestmark = pytest.mark.unit
FIX = Path(__file__).resolve().parent.parent / "fixtures" / "sarif" / "semgrep_sample.sarif"
AWS = "AKIAIOSFODNN7EXAMPLE"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def fixture():
    return json.loads(FIX.read_text())


def test_read_validate_ok():
    assert S.validate(S.read_sarif(FIX)) == []


@pytest.mark.parametrize("mut", [
    lambda d: d.update(version="2.0"), lambda d: d.update(runs={}),
    lambda d: d["runs"][0]["tool"].pop("driver"),
    lambda d: d["runs"][0]["results"][0].pop("message"),
    lambda d: d["runs"][0]["results"][0].update(locations="x"),
])
def test_validate_rejects(mut):
    d = fixture(); mut(d)
    assert S.validate(d)
    with pytest.raises(S.SarifError):
        S.findings_from_sarif(d)


def test_read_malformed(tmp_path):
    p = tmp_path / "x.sarif"; p.write_text("{nope")
    with pytest.raises(S.SarifError):
        S.read_sarif(p)
    with pytest.raises(S.SarifError):
        S.read_sarif(tmp_path / "missing")
    assert S.validate([]) and S.validate(None)


def test_det_write_byte_identical_and_no_timestamps(tmp_path):
    a, b = tmp_path / "a.sarif", tmp_path / "b.sarif"
    d = fixture()
    S.write_sarif(a, d)
    d2 = copy.deepcopy(d)
    d2["runs"][0]["results"].reverse()
    d2["runs"][0]["tool"]["driver"]["rules"].reverse()
    d2["runs"][0]["invocations"][0]["startTimeUtc"] = "2030-05-05T00:00:00Z"
    S.write_sarif(b, d2)
    assert a.read_bytes() == b.read_bytes()
    assert b"TimeUtc" not in a.read_bytes()
    assert a.read_bytes().endswith(b"\n")
    assert S.read_sarif(a)["version"] == "2.1.0"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".sarif-")]


def test_run_order_canonical():
    d = {"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": "z"}}, "results": []}, {"tool": {"driver": {"name": "a"}}, "results": []}]}
    names = [r["tool"]["driver"]["name"] for r in S.canonicalize(d)["runs"]]
    assert names == ["a", "z"]


def test_findings_normalized():
    fs = S.findings_from_sarif(fixture(), "semgrep", root="/work/proj")
    by = {f.rule_ids["semgrep"]: f for f in fs}
    sq = by["py.sqli"]
    assert sq.cwe == ["CWE-89"] and sq.severity == "high"
    assert sq.location == {"path": "app/db.py", "start_line": 12, "end_line": 12}
    assert sq.code_flow == [{"path": "app/views.py", "line": 3, "note": "source"}]
    assert by["py.abc"].severity == "critical" and by["py.abc"].cwe == []
    assert S.findings_from_sarif(fixture(), "semgrep", root="/work/proj") == fs  # deterministic


def test_fingerprint_stable_across_prefix_and_os():
    base = dict(rule_id="R1", cwe=["CWE-89"], start_line=12, snippet="x = 1")
    ps = [S.normalize_path(u, r) for u, r in [
        ("/work/proj/src/x.py", "/work/proj"), ("C:\\w\\proj\\src\\x.py", "C:\\w\\proj"),
        ("file:///tmp/ck/src/x.py", "/tmp/ck"), ("./src/x.py", None), ("src/x.py", None)]]
    assert set(ps) == {"src/x.py"}
    assert len({S.fingerprint(relpath=p, **base) for p in ps}) == 1


def test_fingerprint_normalizations_and_sensitivity():
    f = lambda **k: S.fingerprint(**{**dict(rule_id="R1", cwe=["CWE-89"], relpath="a.py", start_line=12, snippet="a  b"), **k})
    assert f() == f(rule_id=" r1 ") == f(snippet="a\n b") == f(cwe=["cwe-89"])
    assert f() != f(relpath="b.py") and f() != f(cwe=[]) and f() != f(rule_id="R2") and f() != f(snippet="c")


def test_line_bucket_boundary():
    fp = lambda n: S.fingerprint("r", [], "a.py", n, "s")
    assert fp(4) == fp(7)          # same bucket
    assert fp(4) != fp(8)          # delta 4 always differs
    assert S.line_bucket(3) != S.line_bucket(4)


@pytest.mark.parametrize("secret", [AWS, GH, "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----",
                                    "eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4"])
def test_redact_patterns(secret):
    out, changed = redact(f"found {secret} here")
    assert changed and secret not in out


def test_redact_kv_and_clean():
    out, ch = redact('password = "hunter2hunter2"')
    assert ch and "hunter2" not in out and out.startswith("password")
    assert redact("plain message about SQL") == ("plain message about SQL", False)


def test_redaction_in_every_field(tmp_path):
    d = fixture()
    r = d["runs"][0]["results"][0]
    r["message"]["text"] = f"leaked {AWS}"
    r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] = f"key={GH}"
    r["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["message"]["text"] = f"tok {GH}"
    r["partialFingerprints"] = {"k": AWS}
    fs = S.findings_from_sarif(d, "gitleaks")
    blob = json.dumps([f.to_dict() for f in fs])
    assert AWS not in blob and GH not in blob
    assert all(f.secret_redacted for f in fs if "REDACTED" in json.dumps(f.to_dict()))
    assert any(f.secret_redacted for f in fs)
    out = tmp_path / "o.sarif"
    S.write_sarif(out, d)
    txt = out.read_text()
    assert AWS not in txt and GH not in txt
    # fingerprint must not depend on the secret value
    d2 = copy.deepcopy(d)
    d2["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] = "key=ghp_" + "Z" * 36
    assert [f.fingerprint for f in S.findings_from_sarif(d2, "gitleaks")] == [f.fingerprint for f in fs]


def test_secret_scanner_flag():
    fs = S.findings_from_sarif(fixture(), "gitleaks", is_secret_scanner=True)
    assert all(f.secret_redacted for f in fs)
