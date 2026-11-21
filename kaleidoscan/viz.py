"""`kaleidoscan viz`: self-contained, offline, deterministic HTML visualizer for a run envelope (C3).

Server-side rendered (every string passes html.escape); inline JS only filters/selects. No external
resources, no timestamps added (only values already in the envelope).
"""
from __future__ import annotations

import json
from html import escape as e
from pathlib import Path

from kaleidoscan import __version__, catalog

SAMPLE_DIR = Path(__file__).parent / "data" / "sample-run"
SEVS = ("critical", "high", "medium", "low", "info")
SEV_COLOR = {"critical": "#ff2a85", "high": "#ffb800", "medium": "#38bdf8", "low": "#5eead4", "info": "#94a3b8"}
STATUS_COLOR = {"ok": "#00ff9d", "empty": "#ffb800", "skipped": "#94a3b8", "error": "#ff2a85", "timeout": "#ff2a85"}


def load_run(run_dir: Path | str) -> dict:
    d = Path(run_dir)
    p = d / "summary.json"
    if not p.is_file():
        raise ValueError(f"no summary.json in {d}")
    try:
        run = json.loads(p.read_text())
    except json.JSONDecodeError as ex:
        raise ValueError(f"summary.json is not valid JSON: {ex}") from ex
    if not isinstance(run, dict):
        raise ValueError("summary.json must be an object")
    sarif = d / "results.sarif"
    if sarif.is_file() and run.get("schema") == "kaleidoscan.run/1":
        try:
            _merge_sarif_flows(run, json.loads(sarif.read_text()))
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
            pass  # flows are optional enrichment; malformed SARIF never blocks the visualizer
    return run


def _merge_sarif_flows(run: dict, sarif: dict) -> None:
    index: dict[tuple[str, int], list[dict]] = {}
    for r in sarif.get("runs", []):
        for res in r.get("results", []):
            loc = res["locations"][0]["physicalLocation"]
            key = (loc["artifactLocation"]["uri"], loc["region"]["startLine"])
            steps = []
            for cf in res.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    for tl in tf.get("locations", []):
                        pl = tl["location"]["physicalLocation"]
                        steps.append({"path": pl["artifactLocation"]["uri"], "line": pl["region"]["startLine"],
                                      "note": tl["location"].get("message", {}).get("text", "")})
            if steps:
                index[key] = steps
    for f in run.get("findings", []):
        if not f.get("code_flow"):
            steps = index.get((f["location"]["path"], f["location"]["start_line"]))
            if steps:
                f["code_flow"] = steps


def _view_of(f: dict) -> str:
    return "consensus" if len(f["scanner_ids"]) >= 2 else "unique"


def _data(run: dict) -> dict:
    per = {s["id"]: 0 for s in run["scanners"]}
    for f in run["findings"]:
        for sid in f["scanner_ids"]:
            per[sid] = per.get(sid, 0) + 1
    return {
        "consensus": sum(1 for f in run["findings"] if len(f["scanner_ids"]) >= 2),
        "unique": sum(1 for f in run["findings"] if len(f["scanner_ids"]) < 2),
        "taint": sum(1 for f in run["findings"] if f.get("code_flow")),
        "per_scanner": per,
        "counts": run["counts"],
    }


def _stage_detail(sid: str, run: dict, d: dict) -> tuple[str, str]:
    """(state, detail) for a pipeline stage given only what the envelope proves."""
    sc = run["scanners"]
    ok = sum(1 for s in sc if s["status"] == "ok")
    if sid == "target":
        return "done", f'{run["target"]["kind"]} {run["target"]["path"]} ({", ".join(run["target"]["languages"])})'
    if sid == "scan":
        return "done", f"{ok}/{len(sc)} scanners ok"
    if sid == "normalize":
        return "done", f'{sum(len(f["scanner_ids"]) for f in run["findings"])} raw -> {len(run["findings"])} findings'
    if sid == "score":
        return "pending", "scores not present in this envelope (Task 8a)"
    if sid == "views":
        return "done", f'{d["consensus"]} consensus, {d["unique"]} unique, {d["taint"]} taint flows'
    if sid == "gate":
        g = run["gate"]
        return ("done" if g["passed"] else "fail"), ("passed" if g["passed"] else "failed: " + ", ".join(g["reasons"]))
    if sid == "reports":
        return "done", "this page is a report view of summary.json"
    return "pending", "not run (remediation flow, tasks R1-R4)"


def _stages(run: dict, d: dict) -> str:
    out = []
    for i, (sid, label, desc) in enumerate(catalog.STAGES, 1):
        state, detail = _stage_detail(sid, run, d)
        out.append(f'<li class="stage {state}" data-stage="{e(sid)}" data-state="{state}" tabindex="0">'
                   f'<span class="n">{i:02d}</span><b>{e(label)}</b><small>{e(desc)}</small>'
                   f'<em>{e(detail)}</em></li>')
    return "\n".join(out)


def _fanout(run: dict, d: dict) -> str:
    sc = run["scanners"]
    h = max(120, 56 * len(sc) + 20)
    mx = max([d["per_scanner"].get(s["id"], 0) for s in sc] + [1])
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 760 {h}" role="img" '
             f'aria-label="Scanner fan-out: target to {len(sc)} scanners to merged findings">']
    cy = h / 2
    parts.append(f'<rect x="10" y="{cy-22}" width="110" height="44" rx="8" class="node"/>'
                 f'<text x="65" y="{cy+5}" text-anchor="middle" class="t">target</text>')
    parts.append(f'<rect x="640" y="{cy-22}" width="110" height="44" rx="8" class="node"/>'
                 f'<text x="695" y="{cy+5}" text-anchor="middle" class="t">{len(run["findings"])} findings</text>')
    for i, s in enumerate(sc):
        y = 38 + i * 56
        n = d["per_scanner"].get(s["id"], 0)
        col = STATUS_COLOR.get(s["status"], "#94a3b8")
        w = 1.5 + 5 * n / mx
        parts.append(f'<path d="M120 {cy} C 220 {cy}, 220 {y}, 290 {y}" class="edge"/>'
                     f'<path d="M470 {y} C 560 {y}, 560 {cy}, 640 {cy}" class="edge" style="stroke-width:{w:.1f}"/>')
        parts.append(f'<g data-scanner="{e(s["id"])}" data-status="{e(s["status"])}">'
                     f'<rect x="290" y="{y-20}" width="180" height="40" rx="8" class="node" style="stroke:{col}"/>'
                     f'<text x="300" y="{y-3}" class="t">{e(s["id"])}</text>'
                     f'<text x="300" y="{y+13}" class="s" fill="{col}">{e(s["status"])} · {n} findings</text></g>')
    parts.append("</svg>")
    return "".join(parts)


def _bars(run: dict) -> str:
    c = run["counts"]
    mx = max([c.get(k, 0) for k in SEVS] + [1])
    rows = []
    for k in SEVS:
        v = c.get(k, 0)
        rows.append(f'<div class="bar"><span>{k}</span><i style="width:{100*v/mx:.0f}%;background:{SEV_COLOR[k]}"></i>'
                    f'<b>{v}</b></div>')
    return "\n".join(rows)


def _flow(f: dict) -> str:
    steps = "".join(f'<li><code>{e(s["path"])}:{e(str(s["line"]))}</code> {e(s.get("note", ""))}</li>'
                    for s in f["code_flow"])
    return f'<details class="flow"><summary>taint flow ({len(f["code_flow"])} steps)</summary><ol>{steps}</ol></details>'


def _findings(run: dict) -> str:
    if not run["findings"]:
        return '<p class="empty">No findings in this run.</p>'
    order = {k: i for i, k in enumerate(SEVS)}
    rows = []
    for f in sorted(run["findings"], key=lambda x: (order.get(x["severity"], 9), x["location"]["path"], x["location"]["start_line"], x["fingerprint"])):
        views = [_view_of(f)] + (["taint-flows"] if f.get("code_flow") else [])
        loc = f["location"]
        rows.append(
            f'<tr data-fingerprint="{e(f["fingerprint"])}" data-severity="{e(f["severity"])}" data-view="{" ".join(views)}">'
            f'<td><span class="sev" style="background:{SEV_COLOR.get(f["severity"], "#94a3b8")}">{e(f["severity"])}</span></td>'
            f'<td>{e(", ".join(f["cwe"]) or "unknown")}</td>'
            f'<td>{e(f["message"])}{" (secret redacted)" if f.get("secret_redacted") else ""}'
            f'{_flow(f) if f.get("code_flow") else ""}</td>'
            f'<td><code>{e(loc["path"])}:{e(str(loc["start_line"]))}</code></td>'
            f'<td>{e(", ".join(f["scanner_ids"]))}</td></tr>')
    return ('<table><thead><tr><th>severity</th><th>cwe</th><th>message</th><th>location</th><th>scanners</th></tr></thead><tbody>'
            + "\n".join(rows) + "</tbody></table>")


CSS = """:root{--bg:#050811;--panel:#0b1326;--cy:#00e5ff;--sky:#38bdf8;--txt:#f0f6fc;--mut:#94a3b8;--ok:#00ff9d}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
background-image:linear-gradient(rgba(0,229,255,.08) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.08) 1px,transparent 1px);background-size:32px 32px}
main{max-width:1100px;margin:0 auto;padding:16px}h1,h2{font-family:ui-monospace,'Cascadia Code',Menlo,Consolas,monospace;color:var(--cy);margin:.2em 0}
h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:1.4em}section,header{background:rgba(11,19,38,.92);border:1.5px solid var(--cy);border-radius:10px;padding:14px;margin:14px 0}
.meta{color:var(--mut);font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}
.gate{display:inline-block;padding:2px 10px;border-radius:6px;font-weight:700;color:#050811}.gate.passed{background:var(--ok)}.gate.failed{background:#ff2a85}
ol.stages{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.stage{border:1px solid var(--sky);border-radius:8px;padding:8px;background:#070d1c;display:flex;flex-direction:column;gap:2px}
.stage .n{color:var(--cy);font-family:ui-monospace,monospace}.stage small{color:var(--mut)}.stage em{font-style:normal;color:#5eead4;font-size:.85rem}
.stage.pending{opacity:.55;border-style:dashed}.stage.fail{border-color:#ff2a85}.stage:focus,.stage:hover{box-shadow:0 0 0 2px var(--cy)}
svg{width:100%;height:auto}.node{fill:#070d1c;stroke:var(--cy);stroke-width:1.5}.edge{fill:none;stroke:var(--sky);stroke-opacity:.6;stroke-width:1.5}
svg .t{fill:var(--txt);font:600 13px ui-monospace,monospace}svg .s{font:12px ui-monospace,monospace}
.bar{display:grid;grid-template-columns:80px 1fr 40px;gap:8px;align-items:center}.bar i{display:block;height:12px;border-radius:3px;min-width:2px}
.bar span{color:var(--mut)}.bar b{text-align:right}
.controls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}button{background:#070d1c;color:var(--txt);border:1px solid var(--sky);border-radius:6px;padding:6px 12px;cursor:pointer;font:inherit}
button[aria-pressed=true]{background:var(--cy);color:#050811}
.tablewrap{overflow-x:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid rgba(56,189,248,.25);vertical-align:top}
th{color:var(--cy);font-family:ui-monospace,monospace;font-size:.8rem}code{color:#5eead4;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.85rem}
.sev{color:#050811;font-weight:700;padding:1px 8px;border-radius:4px;font-size:.8rem}.flow{margin-top:4px;color:var(--mut)}.flow ol{margin:4px 0 0 18px;padding:0}
.empty{color:var(--mut)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}.card{background:#070d1c;border:1px solid var(--sky);border-radius:8px;padding:8px}
.card b{display:block;font-size:1.6rem;color:var(--cy)}
@media (prefers-reduced-motion:no-preference){.stage{transition:box-shadow .15s}}"""

JS = """(function(){var rows=[].slice.call(document.querySelectorAll('tbody tr')),btns=[].slice.call(document.querySelectorAll('button[data-filter]'));
function apply(v){btns.forEach(function(b){b.setAttribute('aria-pressed',String(b.dataset.filter===v))});
rows.forEach(function(r){r.hidden=!(v==='all'||(' '+r.dataset.view+' ').indexOf(' '+v+' ')>-1)})}
btns.forEach(function(b){b.addEventListener('click',function(){apply(b.dataset.filter)})});})();"""


def render_html(run: dict) -> str:
    if run.get("schema") != "kaleidoscan.run/1":
        raise ValueError(f"unsupported schema: {run.get('schema')!r} (expected kaleidoscan.run/1)")
    d = _data(run)
    g = run["gate"]
    blob = json.dumps(d, sort_keys=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    sample = ' <span class="meta">(synthetic sample run, not a real scan)</span>' if run.get("sample") else ""
    filters = "".join(
        f'<button type="button" data-filter="{v}" aria-pressed="{"true" if v == "all" else "false"}">{v} '
        f'({len(run["findings"]) if v == "all" else d["consensus"] if v == "consensus" else d["unique"] if v == "unique" else d["taint"]})</button>'
        for v in ("all", "consensus", "unique", "taint-flows"))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>kaleidoscan run visualizer</title>
<meta name="description" content="Offline visualizer for a kaleidoscan run: pipeline stages, scanner fan-out, views and taint flows.">
<style>{CSS}</style></head><body><main>
<header><h1>kaleidoscan · run visualizer{sample}</h1>
<div class="meta">run {e(run["run_id"])} · {e(run["started_at"])} → {e(run["finished_at"])} · pipeline {e(run["pipeline"])} · kaleidoscan {e(__version__)}</div>
<p>Gate: <span class="gate {"passed" if g["passed"] else "failed"}" data-gate="{"passed" if g["passed"] else "failed"}">{"PASSED" if g["passed"] else "FAILED"}</span>
<span class="meta">{e(", ".join(g["reasons"]))}</span></p></header>
<section aria-labelledby="h-pipe"><h2 id="h-pipe">Pipeline stages</h2><ol class="stages">
{_stages(run, d)}
</ol></section>
<section aria-labelledby="h-fan"><h2 id="h-fan">Scanner fan-out</h2>{_fanout(run, d)}
<p class="meta">Edge width = findings contributed. Amber/grey nodes are EMPTY/SKIPPED scanners: they saw nothing and must not be read as clean.</p></section>
<section aria-labelledby="h-sum"><h2 id="h-sum">Summary</h2><div class="cards">
<div class="card"><b>{run["counts"]["total"]}</b>findings</div><div class="card"><b>{d["consensus"]}</b>consensus (&gt;=2 scanners)</div>
<div class="card"><b>{d["unique"]}</b>unique (1 scanner)</div><div class="card"><b>{d["taint"]}</b>with taint flow</div></div>
<h2>Severity</h2>{_bars(run)}</section>
<section aria-labelledby="h-find"><h2 id="h-find">Findings</h2><div class="controls" role="group" aria-label="view filter">{filters}</div>
<div class="tablewrap">{_findings(run)}</div></section>
<script type="application/json" id="kscan-data">{blob}</script>
<script>{JS}</script></main></body></html>
"""
