import dataclasses
import json
from pathlib import Path

import pytest

from kaleidoscan.types import (Adapter, Finding, RunEnvelope, ScannerInfo, ScannerKind,
                               ScannerResult, ScannerStatus, Target, count_severities)

pytestmark = pytest.mark.unit


def F(fp="a", cwe=("CWE-89",), path="a.py", line=10, sev="high", sid="semgrep"):
    return Finding(fingerprint=fp, scanner_ids=[sid], rule_ids={sid: "r"}, cwe=list(cwe), severity=sev,
                   confidence="high", message="m",
                   location={"path": path, "start_line": line, "end_line": line})


def test_c1_enums_and_frozen():
    assert {k.value for k in ScannerKind} == {"sast", "sca", "secrets", "iac", "container", "dast"}
    assert {s.value for s in ScannerStatus} == {"ok", "empty", "skipped", "error", "timeout"}
    info = ScannerInfo("x", ScannerKind.SAST, frozenset({"*"}), "MIT", False, True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        info.id = "y"
    t = Target(Path("/a"), "repo", frozenset())
    with pytest.raises(dataclasses.FrozenInstanceError):
        t.kind = "dir"
    r = ScannerResult("x", ScannerStatus.OK, None, None, None, 1, "")
    r.detail = "mutable"
    assert Adapter is not None


@pytest.mark.parametrize("delta,expect", [(0, True), (3, True), (4, False)])
def test_merge_line_delta_boundary(delta, expect):
    assert F("a", line=10).mergeable_with(F("b", line=10 + delta, sid="flowscope")) is expect


def test_empty_cwe_never_merges_cross_scanner():
    assert not F("a", cwe=()).mergeable_with(F("b", cwe=(), sid="flowscope"))
    assert F("a", cwe=()).mergeable_with(F("a", cwe=()))  # same exact fingerprint


def test_different_cwe_or_path_not_merged():
    assert not F("a").mergeable_with(F("b", cwe=("CWE-79",)))
    assert not F("a").mergeable_with(F("b", path="b.py"))


def test_envelope_c3_shape_and_counts():
    fs = [F("a", sev="high"), F("b", sev="low", line=40)]
    assert count_severities(fs) == {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0, "total": 2}
    env = RunEnvelope("id", "t0", "t1", {"path": "."}, "default@h", [], fs).to_dict()
    assert env["schema"] == "kaleidoscan.run/1" and env["dynamic"] is None
    assert set(env) == {"schema", "run_id", "started_at", "finished_at", "target", "pipeline",
                        "scanners", "counts", "findings", "gate", "dynamic"}
    assert env["counts"]["total"] == 2
    json.dumps(env)


def test_envelope_findings_order_independent():
    a, b = F("a", line=1), F("b", line=50)
    e1 = RunEnvelope("i", "t", "t", {}, "p", [], [a, b]).to_dict()
    e2 = RunEnvelope("i", "t", "t", {}, "p", [], [b, a]).to_dict()
    assert e1 == e2
