"""T-ADP for the ingestion adapters (binary-analysis, llm-agent-review): fixtures -> SARIF."""
import json
from pathlib import Path

import pytest

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters.agent_ingest import AgentIngestAdapter, convert as agent_convert
from kaleidoscan.adapters.binary_ingest import BinaryIngestAdapter, detect_tool
from kaleidoscan.types import ScannerStatus, Target

pytestmark = pytest.mark.unit

FX = Path(__file__).resolve().parent.parent / "fixtures"


def tgt(path):
    return Target(path=Path(path), kind="dir", languages=frozenset())


def run(adapter, cfg, path):
    return adapter.run(tgt(path), cfg, timeout_s=10)


def rules(res):
    return [r["ruleId"] for r in res.sarif["runs"][0]["results"]]


def test_info_and_detect():
    for a, id_ in ((BinaryIngestAdapter(), "binary-analysis"), (AgentIngestAdapter(), "llm-agent-review")):
        assert a.info.id == id_ and a.info.languages == frozenset({"*"}) and not a.info.restricted
        assert a.detect() == (True, "ingest")
        assert a.applicable(tgt("."))


@pytest.mark.parametrize("name,expected", [
    ("ghidra.json", ["CWE-120", "CWE-787"]),
    ("angr.json", ["CWE-119", "CWE-416"]),
    ("binja.json", ["CWE-787", "CWE-190"]),
    ("report.txt", ["CWE-121", "CWE-121"]),
])
def test_binary_fixtures(name, expected):
    d = FX / "binary-analysis"
    r = run(BinaryIngestAdapter(), {"inputs": [str(d / name)]}, d)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 1
    assert rules(r) == expected
    assert sarif_mod.validate(r.sarif) == []
    assert "kaleidoscan.view" not in r.sarif["runs"][0].get("properties", {})


def test_binary_details():
    d = FX / "binary-analysis"
    r = run(BinaryIngestAdapter(), {"inputs": [str(d / "ghidra.json")]}, d)
    loc = r.sarif["runs"][0]["results"][1]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "FUN_004022b0"
    assert loc["region"]["startLine"] == 0x4022B0
    assert detect_tool(json.loads((d / "angr.json").read_text())) == "angr"
    assert detect_tool([{"hlil_line": 3}]) == "binja"


def test_binary_explicit_tool_and_dict_entry():
    d = FX / "binary-analysis"
    r = run(BinaryIngestAdapter(), {"inputs": [{"path": str(d / "binja.json"), "tool": "binja"}]}, d)
    assert rules(r) == ["CWE-787", "CWE-190"]


def test_no_inputs_skipped():
    for a in (BinaryIngestAdapter(), AgentIngestAdapter()):
        r = run(a, {}, FX)
        assert r.status is ScannerStatus.SKIPPED and "inputs" in r.detail
        assert run(a, {"inputs": []}, FX).status is ScannerStatus.SKIPPED


def test_zero_records_empty(tmp_path):
    (tmp_path / "e.json").write_text('{"findings": []}')
    (tmp_path / "c.txt").write_text("Looks fine.")
    assert run(BinaryIngestAdapter(), {"inputs": [str(tmp_path / "e.json")]}, tmp_path).status is ScannerStatus.EMPTY
    assert run(AgentIngestAdapter(), {"inputs": [str(tmp_path / "c.txt")]}, tmp_path).status is ScannerStatus.EMPTY


def test_agent_json_view_and_redaction():
    d = FX / "llm-agent-review"
    r = run(AgentIngestAdapter(), {"inputs": [str(d / "findings.json")]}, d)
    assert r.status is ScannerStatus.OK
    run_ = r.sarif["runs"][0]
    assert run_["properties"]["kaleidoscan.view"] == "ai-review"
    assert run_["properties"]["telemetry"]["total_tokens"] == 1500
    assert rules(r) == ["CWE-89", "CWE-79"]
    assert "sk-abcdefgh" not in json.dumps(r.sarif)
    assert sarif_mod.validate(r.sarif) == []


def test_agent_markdown_and_text():
    d = FX / "llm-agent-review"
    r = run(AgentIngestAdapter(), {"inputs": [str(d / "review.md"), str(d / "notes.txt")]}, d)
    assert r.status is ScannerStatus.OK and r.files_analyzed == 2
    assert rules(r) == ["CWE-798", "CWE-22", "CWE-078"]
    res = r.sarif["runs"][0]["results"][1]["locations"][0]["physicalLocation"]
    assert res["artifactLocation"]["uri"] == "src/io.py" and res["region"]["startLine"] == 55
    assert r.sarif["runs"][0]["properties"]["telemetry"]["prompt_tokens"] == 1000


def test_agent_fenced_json():
    res, _ = agent_convert('Here:\n```json\n[{"file":"a.py","line":3,"cwe":"CWE-79","message":"x"}]\n```\n')
    assert res[0]["ruleId"] == "CWE-79"


# ---- security: untrusted inputs ----
sec = pytest.mark.security
ADAPTERS = [BinaryIngestAdapter, AgentIngestAdapter]


@sec
@pytest.mark.parametrize("cls", ADAPTERS)
def test_path_traversal_and_outside_rejected(cls, tmp_path):
    allowed = tmp_path / "scan"
    allowed.mkdir()
    outside = tmp_path / "secret.json"
    outside.write_text('{"findings":[{"cwe":"CWE-1","file":"a","line":1}]}')
    for p in (outside, str(allowed / ".." / "secret.json")):
        r = run(cls(), {"inputs": [str(p)]}, allowed)
        assert r.status is ScannerStatus.ERROR and "outside allowed" in r.detail
    # explicit allowed_dirs lets it through
    r = run(cls(), {"inputs": [str(outside)], "allowed_dirs": [str(tmp_path)]}, allowed)
    assert r.status is not ScannerStatus.ERROR


@sec
@pytest.mark.parametrize("cls", ADAPTERS)
def test_symlink_rejected(cls, tmp_path):
    real = tmp_path / "real.json"
    real.write_text('[{"cwe":"CWE-1","file":"a","line":1}]')
    link = tmp_path / "link.json"
    link.symlink_to(real)
    r = run(cls(), {"inputs": [str(link)]}, tmp_path)
    assert r.status is ScannerStatus.ERROR and "symlink" in r.detail


@sec
@pytest.mark.parametrize("cls", ADAPTERS)
def test_non_regular_missing_and_bad_types(cls, tmp_path):
    (tmp_path / "adir").mkdir()
    for bad in (str(tmp_path / "adir"), str(tmp_path / "missing.json"), "", None, 5, "a\x00b"):
        r = run(cls(), {"inputs": [bad]}, tmp_path)
        assert r.status is ScannerStatus.ERROR, bad
    assert run(cls(), {"inputs": 7}, tmp_path).status is ScannerStatus.ERROR
    assert run(cls(), {"inputs": ["x"] * 100}, tmp_path).status is ScannerStatus.ERROR


@sec
@pytest.mark.parametrize("cls", ADAPTERS)
def test_oversize_rejected(cls, tmp_path):
    big = tmp_path / "big.json"
    big.write_text("[" + "0," * 5000 + "0]")
    r = run(cls(), {"inputs": [str(big)], "max_bytes": 1000}, tmp_path)
    assert r.status is ScannerStatus.ERROR and "size cap" in r.detail


@sec
@pytest.mark.parametrize("cls", ADAPTERS)
def test_malformed_json_never_crashes(cls, tmp_path):
    for i, body in enumerate(["{", "[[[[", "null", "42", '"s"', "[1,2,{}]", '{"findings": 5}',
                              "[" * 100000, '{"findings":[{"line":{"a":1},"cwe":[1],"file":{"x":1}}]}',
                              "\xff\xfe\x00bin"]):
        p = tmp_path / f"m{i}.json"
        p.write_bytes(body.encode("utf-8", "replace"))
        r = run(cls(), {"inputs": [str(p)]}, tmp_path)
        assert r.status in (ScannerStatus.OK, ScannerStatus.EMPTY), (body[:20], r.detail)
        if r.sarif:
            assert sarif_mod.validate(r.sarif) == []


@sec
def test_huge_record_count_and_message_capped(tmp_path):
    items = [{"cwe": "CWE-120", "file": "a.c", "line": i + 1, "message": "A" * 600} for i in range(12000)]
    p = tmp_path / "huge.json"
    p.write_text(json.dumps(items))
    r = run(BinaryIngestAdapter(), {"inputs": [str(p)]}, tmp_path)
    res = r.sarif["runs"][0]["results"]
    assert len(res) == 10000 and len(res[0]["message"]["text"]) <= 500
    r2 = run(AgentIngestAdapter(), {"inputs": [str(p)]}, tmp_path)
    assert len(r2.sarif["runs"][0]["results"]) <= 10000
    assert len(r2.sarif["runs"][0]["results"][0]["message"]["text"]) <= 500


@sec
def test_binary_secret_redacted_and_control_chars(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps([{"cwe": "CWE-798", "file": "a\u0007.s", "line": "-5",
                              "message": "password=hunter2 AKIAABCDEFGHIJKLMNOP"}]))
    r = run(BinaryIngestAdapter(), {"inputs": [str(p)]}, tmp_path)
    blob = json.dumps(r.sarif)
    assert "hunter2" not in blob and "AKIAABCD" not in blob and "\\u0007" not in blob
    assert r.sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


@sec
def test_partial_failure_reported(tmp_path):
    ok = tmp_path / "ok.json"
    ok.write_text('[{"cwe":"CWE-120","file":"a.c","line":1}]')
    r = run(BinaryIngestAdapter(), {"inputs": [str(ok), str(tmp_path / "gone.json")]}, tmp_path)
    assert r.status is ScannerStatus.OK and "gone.json" in r.detail


@sec
def test_input_never_executed(tmp_path):
    marker = tmp_path / "pwned"
    p = tmp_path / "x.py"
    p.write_text(f"open({str(marker)!r}, 'w')\n")
    run(BinaryIngestAdapter(), {"inputs": [str(p)]}, tmp_path)
    run(AgentIngestAdapter(), {"inputs": [str(p)]}, tmp_path)
    assert not marker.exists()
