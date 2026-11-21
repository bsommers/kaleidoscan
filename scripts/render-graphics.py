#!/usr/bin/env python3
"""Deterministic generator for brand kit, diagrams, docs data and the Pages shell.

Writes (relative to --root, default repo root):
  assets/logo.{svg,png}                  square icon 512x512
  docs/assets/logo.{svg,png}             hero banner 1200x360
  docs/assets/icon.{svg,png}             square icon (favicon/OG source)
  docs/assets/icons/icon-<layer>.svg     64x64 category icons (+ .png)
  docs/assets/examples/*.{svg,png}       diagrams (counts from kaleidoscan.catalog + sample run)
  docs/scanners.md, docs/data.json       generated catalog + derived counts
  docs/examples/visualizer.html          sample-run visualizer
  docs/index.html                        GitHub Pages landing page
Usage: render-graphics.py [--root DIR] [--no-png]
No network, no timestamps, no randomness: running twice yields byte-identical SVG/HTML/MD/JSON.
"""
from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from html import escape
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from kaleidoscan import __version__, catalog, viz  # noqa: E402

BG, CY, SKY, PLASMA = "#050811", "#00e5ff", "#38bdf8", "#0284c7"
EMER, AMBER, MAG, ICE, SLATE, PANEL = "#00ff9d", "#ffb800", "#ff2a85", "#f0f6fc", "#94a3b8", "#0b1326"
MONO = "ui-monospace, 'Cascadia Code', 'Fira Code', Menlo, Consolas, monospace"
SANS = "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
REPO_NAME = "kaleidoscan"


def esc(s: str) -> str:
    return escape(str(s), quote=True)


def hexpts(cx, cy, r, rot=-90.0):
    return " ".join(f"{cx + r * math.cos(math.radians(rot + 60 * i)):.1f},{cy + r * math.sin(math.radians(rot + 60 * i)):.1f}" for i in range(6))


class Svg:
    """Tiny SVG builder with neon-grid theme and a text-overflow gate."""

    def __init__(self, w, h, title, desc, grid=True):
        self.w, self.h, self.title, self.desc = w, h, title, desc
        self.parts: list[str] = []
        self.grid = grid

    def add(self, s):
        self.parts.append(s)

    def text(self, x, y, s, size=13, fill=ICE, anchor="start", mono=True, weight=400, maxw=None):
        if maxw is not None and len(s) * size * 0.62 > maxw:
            raise ValueError(f"text overflows {maxw}px: {s!r}")
        fam = MONO if mono else SANS
        self.add(f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{esc(s)}</text>')

    def box(self, x, y, w, h, title, lines=(), accent=CY, size=12, dashed=False):
        dash = ' stroke-dasharray="6 4"' if dashed else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{PANEL}" fill-opacity="0.92" stroke="{accent}" stroke-width="1.5"{dash}/>')
        ts = size + 1
        while len(title) * ts * 0.62 > w - 24 and ts > 9:
            ts -= 1
        self.text(x + 12, y + 20, title, ts, ICE, weight=700, maxw=w - 24)
        n = max(8, int((w - 24) / (size * 0.62)))
        k = 0
        for i, ln in enumerate(lines):
            for piece in _wrap(ln, n):
                self.text(x + 12, y + 40 + k * (size + 5), piece, size, SLATE if i else CY, maxw=w - 24)
                k += 1

    def arrow(self, x1, y1, x2, y2, color=SKY, label=None):
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="2" marker-end="url(#ah)"/>')
        if label:
            self.text((x1 + x2) / 2, (y1 + y2) / 2 - 6, label, 10, SLATE, "middle")

    def render(self):
        grid = ""
        if self.grid:
            grid = (f'<pattern id="g" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="{CY}" stroke-opacity="0.12" stroke-width="1"/></pattern>'
                    f'<rect width="{self.w}" height="{self.h}" fill="url(#g)"/>')
        defs = (f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="{SKY}"/></marker>'
                f'<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{BG}"/><stop offset="1" stop-color="#0a0f1d"/></linearGradient></defs>')
        body = "".join(self.parts)
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" role="img" aria-labelledby="t d">'
                f'<title id="t">{esc(self.title)}</title><desc id="d">{esc(self.desc)}</desc>{defs}'
                f'<rect width="{self.w}" height="{self.h}" fill="url(#bg)"/>{grid}{body}</svg>\n')


# ---------------------------------------------------------------- brand kit
def emblem(cx, cy, r, sw, with_beams=True):
    """Hex shield + inner ring + fan-in beams converging on a diamond core. All strokes >= sw."""
    s = []
    s.append(f'<polygon points="{hexpts(cx, cy, r)}" fill="{PANEL}" stroke="{CY}" stroke-width="{sw}" stroke-linejoin="round"/>')
    s.append(f'<polygon points="{hexpts(cx, cy, r * 0.72, -60)}" fill="none" stroke="{SKY}" stroke-width="{sw}" stroke-linejoin="round" stroke-dasharray="{sw * 3} {sw * 2}"/>')
    if with_beams:
        for k in (-1, 0, 1):  # three scanner views fan in from the left edge
            x0, y0 = cx - r * 0.6, cy + k * r * 0.38
            s.append(f'<line x1="{x0:.1f}" y1="{y0:.1f}" x2="{cx - r * 0.12:.1f}" y2="{cy}" stroke="{SKY}" stroke-width="{sw}" stroke-linecap="round"/>')
            s.append(f'<circle cx="{x0:.1f}" cy="{y0:.1f}" r="{sw * 1.1:.1f}" fill="{CY}"/>')
    d = r * 0.22
    s.append(f'<polygon points="{cx},{cy - d} {cx + d},{cy} {cx},{cy + d} {cx - d},{cy}" fill="{EMER}" stroke="{CY}" stroke-width="{sw}" stroke-linejoin="round"/>')
    s.append(f'<line x1="{cx + d + sw}" y1="{cy}" x2="{cx + r * 0.62:.1f}" y2="{cy}" stroke="{EMER}" stroke-width="{sw}" stroke-linecap="round"/>')
    return "".join(s)


def icon_svg(size=512):
    sw = 12
    s = Svg(512, 512, "kaleidoscan icon", "Hexagonal shield with three scanner views converging on one result", grid=False)
    s.add(f'<rect x="0" y="0" width="512" height="512" rx="96" fill="{BG}"/>')
    s.add(emblem(256, 256, 190, sw))
    return s.render()


def hero_svg():
    c = catalog.counts()
    s = Svg(1200, 360, "kaleidoscan hero banner", "kaleidoscan: composable security testing, many scanners and one ranked result")
    s.add(emblem(190, 180, 130, 6))
    s.text(370, 150, "kaleidoscan", 76, CY, weight=700, maxw=620)
    s.text(374, 196, "MANY SCANNERS. ONE RANKED RESULT.", 22, ICE, mono=True, maxw=700)
    s.text(374, 236, "SARIF 2.1.0 in, ranked views + safe remediation out", 17, SLATE, maxw=700)
    s.text(374, 290, f"v{__version__}  |  {c['scanners']} scanner adapters  |  {c['views']} views  |  {c['stages']} pipeline stages", 15, SKY, maxw=760)
    s.text(374, 316, "local CI = remote CI  |  CLI + HTTP + MCP", 15, EMER, maxw=760)
    s.add(f'<polyline points="1000,40 1160,40 1160,100" fill="none" stroke="{CY}" stroke-width="2"/><polyline points="1000,320 1160,320 1160,260" fill="none" stroke="{CY}" stroke-width="2"/>')
    return s.render()


GLYPHS = {  # 64x64 glyphs, stroke 2.5; each draws inside the 16..48 area
    "scanners": f'<circle cx="32" cy="32" r="13"/><line x1="32" y1="14" x2="32" y2="22"/><line x1="32" y1="42" x2="32" y2="50"/><line x1="14" y1="32" x2="22" y2="32"/><line x1="42" y1="32" x2="50" y2="32"/><circle cx="32" cy="32" r="3" fill="{CY}"/>',
    "normalize": '<path d="M16 20h32M16 32h32M16 44h32"/><path d="M40 14l8 6-8 6M24 38l-8 6 8 6" />',
    "score": '<path d="M16 46V34M26 46V26M36 46V30M46 46V18"/><path d="M14 48h36"/>',
    "report": '<rect x="18" y="14" width="28" height="36" rx="3"/><path d="M24 24h16M24 32h16M24 40h10"/>',
    "mcp": '<circle cx="20" cy="32" r="5"/><circle cx="44" cy="20" r="5"/><circle cx="44" cy="44" r="5"/><path d="M25 30l14-8M25 34l14 8"/>',
    "remediate": '<path d="M32 14l14 6v10c0 9-6 15-14 19-8-4-14-10-14-19V20z"/><path d="M25 32l5 5 9-10"/>',
    "ci": '<path d="M18 38a8 8 0 0 1 2-15 11 11 0 0 1 21-2 8 8 0 0 1 3 17z"/><path d="M26 44l6 6 6-6M32 38v12"/>',
    "dynamic": '<circle cx="32" cy="32" r="14" stroke-dasharray="4 4"/><path d="M26 32h12M32 26v12" stroke-dasharray="3 3"/>',
}


def category_icon(name):
    dim = name == "dynamic"
    col = SLATE if dim else CY
    sk = SLATE if dim else SKY
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-label="{name} icon">'
            f'<rect x="4" y="4" width="56" height="56" rx="12" fill="#070d1c" stroke="{col}" stroke-width="2"/>'
            f'<g fill="none" stroke="{sk}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">{GLYPHS[name]}</g></svg>\n')


# ---------------------------------------------------------------- diagrams
def sample():
    return viz.load_run(viz.SAMPLE_DIR)


def d_architecture():
    s = Svg(1100, 560, "kaleidoscan system architecture", "Surfaces on top, core pipeline in the middle, scanner adapters below")
    s.text(24, 30, "SYSTEM ARCHITECTURE  (layers: surfaces > core > adapters)", 15, CY, weight=700)
    surf = [("CLI", "kaleidoscan | kscan"), ("Python API", "kaleidoscan.api"), ("HTTP", "127.0.0.1 + token"), ("MCP", "forge/FastMCP"), ("CI action", "action.yml")]
    for i, (t, l) in enumerate(surf):
        s.box(24 + i * 214, 50, 198, 62, t, [l], SKY)
    core = [("config.py", "kaleidoscan.yaml (C4)"), ("runner.py", "argv-only, timeouts"), ("normalize.py", "SARIF -> C2 findings"), ("scoring/", "noisy-OR (C15/C16)"),
            ("views.py", f"{len(catalog.VIEWS)} views"), ("policy.py", "gate + baseline"), ("reports/", "sarif html md junit"), ("remediate/", "review plan fix pr")]
    s.add(f'<rect x="24" y="140" width="1052" height="210" rx="10" fill="none" stroke="{CY}" stroke-opacity="0.5" stroke-dasharray="4 4"/>')
    s.text(36, 160, "CORE (surface-agnostic)", 12, CY, weight=700)
    for i, (t, l) in enumerate(core):
        s.box(40 + (i % 4) * 256, 172 + (i // 4) * 84, 240, 72, t, [l], CY, 12)
    for i in range(5):
        s.arrow(123 + i * 214, 112, 123 + i * 214, 140)
    s.arrow(550, 350, 550, 386)
    s.text(566, 372, "Adapter protocol (C1)", 11, SLATE)
    s.text(24, 400, f"ADAPTERS  ({catalog.counts()['scanners']} planned/portfolio, one file each)", 13, CY, weight=700)
    for i, sc in enumerate(catalog.SCANNERS):
        col = AMBER if sc[5] else (CY if sc[6] == "baseline" else SKY)
        s.box(24 + (i % 8) * 132, 414 + (i // 8) * 66, 124, 56, sc[0], [sc[2] + " " + sc[6]], col, 10)
    s.text(24, 552, "amber = restricted license (opt-in) | cyan = baseline parity set | blue = tier A", 11, SLATE)
    return s.render()


def d_pipeline():
    s = Svg(1100, 470, "kaleidoscan pipeline data flow", "Eleven stages from target to pull request")
    s.text(24, 30, "PIPELINE DATA FLOW", 15, CY, weight=700)
    arts = ["path", "raw/<scanner>.*", "findings (C2)", "scores", "views", "gate verdict", "results.sarif report.html", "review.json", "plan.json", "patches", "gh_pr.sh"]
    for i, (sid, label, desc) in enumerate(catalog.STAGES):
        row, col = divmod(i, 6)
        x, y = 24 + col * 176, 60 + row * 190
        s.box(x, y, 160, 150, f"{i + 1:02d} {label}", [arts[i], *_wrap(desc, 21)], MAG if sid == "gate" else (SKY if i > 6 else CY), 11)
        if col < 5 and i < len(catalog.STAGES) - 1:
            s.arrow(x + 160, y + 75, x + 176, y + 75)
    s.text(24, 450, "stages 01-07 = scan/report (implemented over Tasks 1-9) | 08-11 = remediation (R1-R4, human gate before publish)", 12, SLATE)
    return s.render()


def _wrap(text, n):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > n and cur:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + " " + w).strip()
    return lines + [cur]


def d_portfolio():
    rows = catalog.SCANNERS
    s = Svg(1100, 90 + 30 * len(rows), "scanner portfolio", "Table of scanners with kind, tier and license")
    s.text(24, 30, f"SCANNER PORTFOLIO  ({len(rows)} scanners; generated from kaleidoscan/catalog.py)", 15, CY, weight=700)
    for j, h in enumerate(["id", "kind", "tier", "languages", "license"]):
        s.text([24, 190, 290, 360, 760][j], 62, h.upper(), 11, SKY, weight=700)
    for i, sc in enumerate(rows):
        y = 88 + 30 * i
        s.add(f'<line x1="24" y1="{y - 16}" x2="1076" y2="{y - 16}" stroke="{CY}" stroke-opacity="0.15"/>')
        col = AMBER if sc[5] else ICE
        s.text(24, y, sc[0], 12, col, maxw=160)
        s.text(190, y, sc[2], 12, SLATE, maxw=90)
        s.text(290, y, sc[6], 12, SKY, maxw=60)
        s.text(360, y, ", ".join(sc[3])[:48], 12, SLATE, maxw=390)
        s.text(760, y, sc[4] + (" [restricted]" if sc[5] else ""), 12, col, maxw=300)
    return s.render()


def d_scoring():
    p1, p2 = 0.769, 0.50
    pt = 1 - (1 - p1) * (1 - p2)
    s = Svg(1000, 360, "ranking and scoring explainer", "Noisy-OR combination of independent scanner precisions with a worked example")
    s.text(24, 30, "FINDING SCORE  (noisy-OR over independent scanners)", 15, CY, weight=700)
    s.box(24, 50, 952, 70, "p_tp = 1 - PROD_i (1 - precision_i[lang, cwe])", ["scanners sharing an independence_group count once; unscored scanners use neutral prior 0.30 (flagged)"], CY, 12)
    s.box(24, 140, 300, 90, "scanner A  precision 0.769", ["(Flowscope Python, gate 2026-09-13)"], SKY, 11)
    s.box(24, 250, 300, 90, "scanner B  precision 0.500", ["illustrative value, not measured"], SKY, 11)
    s.arrow(324, 185, 440, 240)
    s.arrow(324, 295, 440, 270)
    s.box(440, 200, 536, 110, f"p_tp = 1 - (1-{p1}) x (1-{p2}) = {pt:.3f}", ["two independent reports raise confidence from 0.769 to 0.885", "ranked view orders by p_tp and prints this explanation"], EMER, 12)
    return s.render()


def d_views():
    r = sample()
    d = viz._data(r)
    s = Svg(1100, 420, "views gallery", "The ten views with sample-run counts")
    s.text(24, 30, f"{len(catalog.VIEWS)} VIEWS  (sample run: {len(r['findings'])} findings, {d['consensus']} consensus, {d['unique']} unique, {d['taint']} taint)", 15, CY, weight=700)
    for i, (v, desc) in enumerate(catalog.VIEWS):
        s.box(24 + (i % 5) * 212, 56 + (i // 5) * 170, 200, 150, v, _wrap(desc, 24), CY if i % 2 == 0 else SKY, 11)
    s.text(24, 400, "kaleidoscan findings RUN --view <name>   (planned; visualizer already shows consensus / unique / taint-flows)", 12, SLATE)
    return s.render()


def d_remediation():
    s = Svg(1100, 400, "remediation flow", "Scan, review, plan, remediate with verify and revert loop, then human-gated pull request")
    s.text(24, 30, "REMEDIATION FLOW  (human gate before any publish)", 15, CY, weight=700)
    steps = [("scan", "run -> summary.json"), ("review", "evidence-validated"), ("plan", "det | ai | manual"), ("remediate", "isolated worktree"), ("open-pr", "dry-run default")]
    for i, (t, l) in enumerate(steps):
        s.box(24 + i * 214, 60, 190, 80, f"kaleidoscan {t if t != 'scan' else 'run'}", [l], CY if i < 4 else MAG, 11)
        if i < 4:
            s.arrow(214 + i * 214, 100, 238 + i * 214, 100)
    s.box(24 + 3 * 214, 190, 190, 120, "per-patch loop", ["apply patch", "re-run tests + scan", "fail or new finding:", "revert + downgrade to manual"], AMBER, 11)
    s.arrow(24 + 3 * 214 + 95, 140, 24 + 3 * 214 + 95, 190)
    s.box(24, 190, 400, 120, "limits and guards", ["forbidden globs -> manual", "diff-size limit; manual never patched", "fork PRs refuse apply/push", "untrusted PR text cannot alter the plan"], SKY, 11)
    s.box(24 + 4 * 214, 190, 190, 120, "human gate", ["--confirm required", "to publish a PR", "else gh_pr.sh only"], MAG, 11)
    s.text(24, 350, "tasks R1-R4 (planned); contracts C11-C13", 12, SLATE)
    return s.render()


def d_mcp():
    s = Svg(1100, 300, "MCP forge pipeline", "OpenAPI to MCP Forge to FastMCP server to client")
    s.text(24, 30, "MCP VIA FORGE  (Task 11, planned)", 15, CY, weight=700)
    for i, (t, l) in enumerate([("openapi.yaml", "<=15 ops (C7)"), ("forge create", "dry-run, then --execute"), ("mcp/ server", "FastMCP, mcp<2"), ("client", "Claude / IDE agent")]):
        s.box(24 + i * 270, 60, 230, 80, t, [l], CY, 12)
        if i < 3:
            s.arrow(254 + i * 270, 100, 294 + i * 270, 100)
    tools = ["list_scanners", "run_scan", "get_run", "query_findings", "get_report", "diff_runs", "get_gate"]
    s.text(24, 180, "tools (C8): " + " | ".join(tools[:4]), 12, SKY)
    s.text(24, 202, "             " + " | ".join(tools[4:]), 12, SKY)
    s.text(24, 240, "run_scan returns run_id immediately; target must be under KALEIDOSCAN_ALLOWED_ROOTS", 12, SLATE)
    s.text(24, 262, "validated by forge validate-mcp.sh + T-MCP handshake test", 12, SLATE)
    return s.render()


def d_ci():
    s = Svg(1100, 320, "CI topology", "Local runner and GitHub Actions share one code path")
    s.text(24, 30, "CI TOPOLOGY  (one code path, C10)", 15, CY, weight=700)
    s.box(24, 60, 300, 90, "local", ["scripts/verify.sh", "kaleidoscan run --profile ci"], CY, 12)
    s.box(24, 190, 300, 90, "GitHub Actions", ["action.yml (composite)", "pinned SHAs, least privilege"], SKY, 12)
    s.arrow(324, 105, 440, 165)
    s.arrow(324, 235, 440, 190)
    s.box(440, 130, 280, 80, "kaleidoscan run --profile ci", ["same adapters, no CI-only logic"], EMER, 12)
    s.arrow(720, 170, 780, 170)
    s.box(780, 90, 296, 160, "outputs", ["results.sarif -> code scanning", "report.html -> artifact", "PR runs: diff vs base baseline", "exit code 0..4 = gate"], CY, 12)
    return s.render()


def d_trust():
    s = Svg(1100, 360, "trust boundaries", "Untrusted inputs, trusted core, and mitigations")
    s.text(24, 30, "TRUST BOUNDARIES", 15, CY, weight=700)
    s.box(24, 60, 300, 120, "UNTRUSTED", ["target repo contents", "scanner output", "PR title/body/diff", "MCP client requests"], MAG, 12)
    s.arrow(324, 120, 380, 120)
    s.box(380, 60, 330, 120, "BOUNDARY CONTROLS", ["argv-only subprocess (no shell=True)", "realpath allowed-roots check", "html.escape everywhere; no CDN", "secret redaction at normalization"], AMBER, 12)
    s.arrow(710, 120, 766, 120)
    s.box(766, 60, 310, 120, "TRUSTED CORE", ["timeouts + output caps", "atomic run-dir writes", "loopback HTTP + optional token", "worktree-isolated fixes"], EMER, 12)
    s.text(24, 220, "scanner reports 'ran but saw nothing' (0 files) as EMPTY, never as clean", 13, SKY)
    s.text(24, 246, "dynamic testing (DAST) is reserved only: setting `dynamic:` is an error", 13, SKY)
    return s.render()


def d_visualizer():
    r = sample()
    d = viz._data(r)
    s = Svg(1100, 380, "visualizer overview", "Pipeline stage strip and scanner fan-out from a sample run envelope")
    s.text(24, 30, "kaleidoscan viz RUN_DIR  ->  visualizer.html  (offline, no CDN)", 15, CY, weight=700)
    for i, (sid, label, _) in enumerate(catalog.STAGES):
        st, _detail = viz._stage_detail(sid, r, d)
        col = {"done": EMER, "fail": MAG, "pending": SLATE}[st]
        s.box(24 + i * 96, 56, 88, 50, f"{i + 1:02d}", [sid], col, 10, dashed=(st == "pending"))
    for i, sc in enumerate(r["scanners"]):
        y = 140 + i * 36
        n = d["per_scanner"].get(sc["id"], 0)
        s.add(f'<line x1="140" y1="260" x2="360" y2="{y + 10}" stroke="{SKY}" stroke-opacity="0.5" stroke-width="{1.5 + n}"/>')
        s.text(370, y + 14, f"{sc['id']:<12} {sc['status']:<8} {n} findings", 12, {"ok": EMER, "empty": AMBER}.get(sc["status"], SLATE), maxw=330)
    s.box(24, 230, 116, 60, "target", [r["target"]["kind"]], CY, 11)
    s.add(f'<line x1="700" y1="250" x2="760" y2="250" stroke="{SKY}" stroke-width="2" marker-end="url(#ah)"/>')
    s.box(770, 150, 306, 200, "per-run panels", [f"{d['consensus']} consensus / {d['unique']} unique", f"{d['taint']} taint-flow paths", "severity bars", "filter: all consensus unique taint", "EMPTY/SKIPPED flagged, not clean"], CY, 12)
    return s.render()


DIAGRAMS = {
    "architecture-overview": d_architecture, "pipeline-dataflow": d_pipeline, "scanner-portfolio": d_portfolio,
    "scoring-explainer": d_scoring, "views-gallery": d_views, "remediation-flow": d_remediation,
    "mcp-forge-pipeline": d_mcp, "ci-topology": d_ci, "trust-boundaries": d_trust, "visualizer-overview": d_visualizer,
}
ALT = {
    "architecture-overview": "System architecture: five surfaces over a surface-agnostic core over scanner adapters",
    "pipeline-dataflow": "Pipeline data flow through eleven stages from target to pull request",
    "scanner-portfolio": "Scanner portfolio table generated from the catalog",
    "scoring-explainer": "Noisy-OR finding score with a worked example",
    "views-gallery": "The ten result views with sample-run counts",
    "remediation-flow": "Scan, review, plan, remediate with revert loop, and a human-gated PR",
    "mcp-forge-pipeline": "OpenAPI to Forge to FastMCP server to MCP client",
    "ci-topology": "Local runner and GitHub Actions share one code path",
    "trust-boundaries": "Untrusted inputs, boundary controls and trusted core",
    "visualizer-overview": "Visualizer: stage strip, scanner fan-out and per-run panels from a sample run",
}


# ---------------------------------------------------------------- generated docs
def scanners_md():
    c = catalog.counts()
    out = ["# Scanner portfolio", "", "<!-- generated by scripts/render-graphics.py from kaleidoscan/catalog.py; do not edit -->", "",
           f"{c['scanners']} scanners ({c['scanners_baseline']} baseline parity, {c['scanners_tier_a']} tier A; {c['scanners_restricted']} restricted/opt-in). "
           "All are **planned** adapters: none is implemented yet (Tasks 5-7b). Scores come from the Synth benchmark (Task 13); until then every scanner is `unscored`.",
           "", "| id | name | kind | tier | languages | license | restricted |", "|---|---|---|---|---|---|---|"]
    for sid, name, kind, langs, lic, res, tier in catalog.SCANNERS:
        out.append(f"| `{sid}` | {name} | {kind} | {tier} | {', '.join(langs)} | {lic} | {'yes' if res else 'no'} |")
    out += ["", f"## Views ({c['views']})", "", "| view | meaning |", "|---|---|"] + [f"| `{v}` | {d} |" for v, d in catalog.VIEWS]
    out += ["", f"## Pipeline stages ({c['stages']})", "", "| # | stage | what happens |", "|---|---|---|"] + [f"| {i} | {l} | {d} |" for i, (_, l, d) in enumerate(catalog.STAGES, 1)]
    return "\n".join(out) + "\n"


def data_json():
    return json.dumps({"version": __version__, "counts": catalog.counts(),
                       "scanners": [dict(zip(("id", "name", "kind", "languages", "license", "restricted", "tier"), s)) for s in catalog.SCANNERS],
                       "views": [v for v, _ in catalog.VIEWS], "commands": [{"name": n, "status": st} for n, st in catalog.COMMANDS]},
                      indent=2, sort_keys=True) + "\n"


def index_html():
    c = catalog.counts()
    data = json.dumps([dict(zip(("id", "name", "kind", "languages", "license", "restricted", "tier"), s)) for s in catalog.SCANNERS]).replace("<", "\\u003c")
    cards = [("purpose.md", "Purpose", "problem, tenets, threat model"), ("architecture.md", "Architecture", "layers, adapters, data flow"),
             ("running.md", "Running", "install, CLI, exit codes"), ("configuration.md", "Configuration", "kaleidoscan.yaml reference"),
             ("how-to.md", "How-to", "recipes"), ("scanners.md", "Scanners", "generated catalog"),
             ("views-and-scoring.md", "Views and scoring", "noisy-OR, ranking"), ("remediation.md", "Remediation", "review, plan, fix, PR"),
             ("integrations.md", "HTTP, MCP, CI", "surfaces"), ("usermanual/README.md", "User manual", "guided reading"),
             ("CONTRIBUTING.md", "Contributing", "adapters, tests, docs")]
    cardhtml = "\n".join(f'<a class="card" href="{h}"><b>{t}</b><span>{d}</span></a>' for h, t, d in cards)
    gal = "\n".join(f'<figure><a href="assets/examples/{n}.png"><img src="assets/examples/{n}.svg" alt="{esc(ALT[n])}" loading="lazy"></a><figcaption>{esc(ALT[n])}</figcaption></figure>' for n in DIAGRAMS)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>kaleidoscan</title>
<meta name="description" content="Composable security testing: many scanners, one normalized SARIF result, ranked views and safe remediation.">
<meta property="og:title" content="kaleidoscan"><meta property="og:description" content="Many scanners. One ranked result.">
<meta property="og:type" content="website"><meta property="og:image" content="assets/logo.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" type="image/svg+xml" href="assets/icon.svg">
<style>
:root{{--bg:#050811;--cy:#00e5ff;--sky:#38bdf8;--txt:#f0f6fc;--mut:#94a3b8;--panel:#0b1326}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--txt);font:16px/1.55 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
background-image:linear-gradient(rgba(0,229,255,.1) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.1) 1px,transparent 1px);background-size:32px 32px}}
main{{max-width:1100px;margin:0 auto;padding:16px}}a{{color:var(--sky)}}h2{{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--cy)}}
.hero img{{width:100%;height:auto;border:1.5px solid var(--cy);border-radius:10px}}
section{{background:rgba(11,19,38,.92);border:1.5px solid var(--cy);border-radius:10px;padding:14px 16px;margin:16px 0}}
.counts{{display:flex;gap:12px;flex-wrap:wrap}}.counts div{{border:1px solid var(--sky);border-radius:8px;padding:6px 12px}}.counts b{{color:var(--cy);font-size:1.4rem;display:block}}
pre{{background:#070d1c;border:1px solid var(--sky);border-radius:8px;padding:10px;overflow-x:auto;color:#5eead4;margin:0}}
button,input,select{{background:#070d1c;color:var(--txt);border:1px solid var(--sky);border-radius:6px;padding:6px 10px;font:inherit}}
.gallery{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}}figure{{margin:0}}figure img{{width:100%;height:auto;border:1px solid var(--sky);border-radius:8px}}
figcaption{{color:var(--mut);font-size:.85rem}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}}
.card{{display:block;border:1px solid var(--sky);border-radius:8px;padding:10px;text-decoration:none;background:#070d1c}}.card b{{display:block;color:var(--cy)}}.card span{{color:var(--mut);font-size:.9rem}}
table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;padding:4px 8px;border-bottom:1px solid rgba(56,189,248,.25)}}.tw{{overflow-x:auto}}
.row{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}}
@media (prefers-reduced-motion:no-preference){{.card{{transition:box-shadow .15s}}.card:hover{{box-shadow:0 0 0 2px var(--cy)}}}}
</style></head><body><main>
<div class="hero"><img src="assets/logo.svg" alt="kaleidoscan hero banner: many scanners, one ranked result"></div>
<section><p>Composable security testing: run several scanners over one target, normalize everything to SARIF 2.1.0, rank by measured scanner reliability, and gate in local or remote CI. Early development: see <a href="https://github.com/">status</a> in the README for what is implemented.</p>
<div class="counts" id="counts"><div><b>{c['scanners']}</b>scanner adapters (planned)</div><div><b>{c['views']}</b>views</div><div><b>{c['stages']}</b>pipeline stages</div><div><b>{c['commands_implemented']}/{c['commands']}</b>commands implemented</div><div><b>v{__version__}</b>version</div></div>
<p><a href="examples/visualizer.html">Open the interactive pipeline visualizer (sample run)</a> · <a href="usermanual/README.md">User manual</a></p></section>
<section><h2>Quickstart</h2>
<div class="row"><button type="button" data-copy="uv tool install .">copy install</button></div><pre id="q1">uv tool install .
kaleidoscan doctor
kaleidoscan viz --sample --out visualizer.html</pre></section>
<section><h2>Graphics</h2><div class="gallery">
{gal}
</div></section>
<section><h2>Scanner explorer</h2><div class="row"><input id="q" type="search" placeholder="search scanners" aria-label="search scanners">
<select id="k" aria-label="kind"><option value="">all kinds</option><option>sast</option><option>sca</option><option>secrets</option><option>iac</option></select>
<select id="t" aria-label="tier"><option value="">all tiers</option><option>baseline</option><option>A</option></select></div>
<div class="tw"><table><thead><tr><th>id</th><th>kind</th><th>tier</th><th>languages</th><th>license</th></tr></thead><tbody id="rows"></tbody></table></div></section>
<section><h2>Documentation</h2><div class="cards">
{cardhtml}
</div></section>
<script type="application/json" id="scanners-data">{data}</script>
<script>
(function(){{var S=JSON.parse(document.getElementById('scanners-data').textContent),tb=document.getElementById('rows');
function draw(){{var q=document.getElementById('q').value.toLowerCase(),k=document.getElementById('k').value,t=document.getElementById('t').value;tb.textContent='';
S.forEach(function(s){{var txt=(s.id+' '+s.name+' '+s.languages.join(' ')+' '+s.license).toLowerCase();
if((q&&txt.indexOf(q)<0)||(k&&s.kind!==k)||(t&&s.tier!==t))return;var tr=document.createElement('tr');
[s.id,s.kind,s.tier,s.languages.join(', '),s.license+(s.restricted?' [restricted]':'')].forEach(function(v){{var td=document.createElement('td');td.textContent=v;tr.appendChild(td)}});tb.appendChild(tr)}})}}
['q','k','t'].forEach(function(i){{document.getElementById(i).addEventListener('input',draw)}});draw();
document.querySelectorAll('button[data-copy]').forEach(function(b){{b.addEventListener('click',function(){{if(navigator.clipboard)navigator.clipboard.writeText(b.dataset.copy)}})}});}})();
</script></main></body></html>
"""


# ---------------------------------------------------------------- driver
def svg_to_png(svg: Path, png: Path, width: int) -> bool:
    exe = shutil.which("inkscape") or shutil.which("rsvg-convert") or shutil.which("convert")
    if not exe:
        return False
    name = Path(exe).name
    if name == "inkscape":
        cmd = [exe, str(svg), "--export-type=png", f"--export-filename={png}", f"--export-width={width}"]
    elif name == "rsvg-convert":
        cmd = [exe, "-w", str(width), "-o", str(png), str(svg)]
    else:
        cmd = [exe, "-background", "none", "-resize", f"{width}x", str(svg), str(png)]
    return subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL).returncode == 0 and png.is_file()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(REPO))
    ap.add_argument("--no-png", action="store_true")
    a = ap.parse_args(argv)
    root = Path(a.root)
    files: dict[str, str] = {
        "assets/logo.svg": icon_svg(), "docs/assets/icon.svg": icon_svg(), "docs/assets/logo.svg": hero_svg(),
        "docs/scanners.md": scanners_md(), "docs/data.json": data_json(), "docs/index.html": index_html(),
        "docs/examples/visualizer.html": viz.render_html(sample()),
    }
    for name in GLYPHS:
        files[f"docs/assets/icons/icon-{name}.svg"] = category_icon(name)
    for n, fn in DIAGRAMS.items():
        files[f"docs/assets/examples/{n}.svg"] = fn()
    for rel, text in sorted(files.items()):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (root / "docs" / ".nojekyll").touch()
    if not a.no_png:
        jobs = {"assets/logo": 512, "docs/assets/icon": 512, "docs/assets/logo": 1200}
        jobs |= {f"docs/assets/icons/icon-{n}": 128 for n in GLYPHS}
        jobs |= {f"docs/assets/examples/{n}": 1600 for n in DIAGRAMS}
        missing = [b for b, w in sorted(jobs.items()) if not svg_to_png(root / f"{b}.svg", root / f"{b}.png", w)]
        if missing:
            print("PNG rasterization failed (need inkscape, rsvg-convert or ImageMagick) for: " + ", ".join(missing), file=sys.stderr)
            return 1
    print(f"wrote {len(files)} generated files" + ("" if a.no_png else " + PNGs"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
