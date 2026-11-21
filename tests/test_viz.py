"""Visualizer tests: structure, determinism, escaping, offline, CLI, golden sample."""
import copy
import json
import re
from pathlib import Path

import pytest

from kaleidoscan import catalog
from kaleidoscan.viz import SAMPLE_DIR, load_run, render_html

pytestmark = pytest.mark.unit


@pytest.fixture
def run():
    return load_run(SAMPLE_DIR)


def test_all_pipeline_stages_present(run):
    html = render_html(run)
    for sid, label, _ in catalog.STAGES:
        assert f'data-stage="{sid}"' in html and label in html


def test_scanners_and_statuses_rendered(run):
    html = render_html(run)
    for s in run["scanners"]:
        assert f'data-scanner="{s["id"]}"' in html
    assert 'data-status="empty"' in html and 'data-status="skipped"' in html


def test_findings_and_flows(run):
    html = render_html(run)
    assert html.count('data-fingerprint="') == len(run["findings"])
    assert "cursor.execute(query)" in html  # code flow step rendered
    for v in ("consensus", "unique", "taint-flows"):
        assert re.search(rf'data-view="[^"]*\b{v}\b', html), v


def test_consensus_unique_counts_in_embedded_data(run):
    html = render_html(run)
    m = re.search(r'<script type="application/json" id="kscan-data">(.*?)</script>', html, re.S)
    data = json.loads(m.group(1))
    assert data["consensus"] == sum(1 for f in run["findings"] if len(f["scanner_ids"]) >= 2) == 2
    assert data["unique"] == 6 and data["taint"] == 2
    assert data["per_scanner"]["semgrep"] == 4


def test_deterministic(run):
    assert render_html(run) == render_html(copy.deepcopy(run))


def test_offline_no_external_refs(run):
    html = render_html(run)
    stripped = html.replace("http://www.w3.org/2000/svg", "")
    assert not re.search(r"https?://", stripped)
    assert not re.search(r"<script[^>]+src=|<link[^>]+href=|@import|<img[^>]+src=\"http", html)


def test_malicious_strings_escaped(run):
    r = copy.deepcopy(run)
    payload = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    r["findings"][0]["message"] = payload
    r["findings"][0]["location"]["path"] = payload
    r["findings"][0]["code_flow"][0]["note"] = payload
    r["scanners"][0]["detail"] = payload
    html = render_html(r)
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    # JSON blob must not be able to close its script tag
    blob = re.search(r'id="kscan-data">(.*?)</script>', html, re.S).group(1)
    assert "</" not in blob and "<" not in blob


def test_empty_findings_run(run):
    r = copy.deepcopy(run)
    r["findings"] = []
    r["counts"] = {k: 0 for k in r["counts"]}
    r["gate"] = {"passed": True, "reasons": []}
    html = render_html(r)
    assert "No findings" in html and 'data-gate="passed"' in html


def test_rejects_bad_schema():
    with pytest.raises(ValueError):
        render_html({"schema": "other/9"})


def test_load_run_errors(tmp_path):
    with pytest.raises(ValueError):
        load_run(tmp_path)  # no summary.json
    (tmp_path / "summary.json").write_text("{not json")
    with pytest.raises(ValueError):
        load_run(tmp_path)


def test_sarif_codeflows_merged(tmp_path, run):
    r = copy.deepcopy(run)
    r["findings"][0]["code_flow"] = None
    d = tmp_path
    (d / "summary.json").write_text(json.dumps(r))
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "flowscope"}}, "results": [{
        "ruleId": "FS-PY-SQLI-001",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/db.py"}, "region": {"startLine": 47}}}],
        "codeFlows": [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {"artifactLocation": {"uri": "app/a.py"}, "region": {"startLine": 1}},
                          "message": {"text": "from-sarif-step"}}}]}]}]}]}]}
    (d / "results.sarif").write_text(json.dumps(sarif))
    assert "from-sarif-step" in render_html(load_run(d))


def test_cli_viz_writes_file(run_cli, tmp_path):
    out = tmp_path / "v.html"
    r = run_cli("viz", "--sample", "--out", str(out))
    assert r.returncode == 0 and out.read_text().startswith("<!doctype html>")


def test_cli_viz_run_dir_and_errors(run_cli, tmp_path):
    assert run_cli("viz", str(tmp_path / "nope")).returncode == 2
    assert run_cli("viz").returncode == 2
    d = tmp_path / "r"
    d.mkdir()
    (d / "summary.json").write_text((SAMPLE_DIR / "summary.json").read_text())
    r = run_cli("viz", str(d))
    assert r.returncode == 0 and (d / "visualizer.html").exists()


def test_golden_sample_matches_committed(root):
    golden = root / "docs" / "examples" / "visualizer.html"
    assert golden.read_text() == render_html(load_run(SAMPLE_DIR)), "run scripts/render-graphics.py to refresh"
