"""T-DOC: docs, graphics and Pages cannot drift from code. No network."""
import ast
import json
import re
import shlex
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import kaleidoscan
from kaleidoscan import catalog

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parent.parent
MD = sorted([ROOT / "README.md", *(ROOT / "docs").rglob("*.md")])
REQUIRED_DOCS = ["README.md", "docs/README.md", "docs/purpose.md", "docs/architecture.md", "docs/running.md",
                 "docs/configuration.md", "docs/how-to.md", "docs/scanners.md", "docs/views-and-scoring.md",
                 "docs/remediation.md", "docs/integrations.md", "docs/visualizer.md", "docs/CONTRIBUTING.md",
                 "docs/CHANGELOG.md", "docs/usermanual/README.md", "docs/index.html", "docs/.nojekyll",
                 ".github/workflows/pages.yml", "docs/examples/visualizer.html"]


def test_required_files_exist():
    assert [p for p in REQUIRED_DOCS if not (ROOT / p).exists()] == []


def _links(text):
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    return re.findall(r"!?\[[^\]]*\]\(([^)\s]+)\)", text)


def test_markdown_relative_links_resolve():
    bad = []
    for f in MD:
        for link in _links(f.read_text()):
            if re.match(r"[a-z]+:", link) or link.startswith("#"):
                continue
            if not (f.parent / link.split("#")[0]).exists():
                bad.append(f"{f.relative_to(ROOT)} -> {link}")
    assert bad == []


def test_html_relative_refs_resolve():
    bad = []
    for f in (ROOT / "docs" / "index.html", ROOT / "docs" / "examples" / "visualizer.html"):
        for m in re.findall(r'(?:src|href)="([^"]+)"', f.read_text()):
            if re.match(r"[a-z]+:", m) or m.startswith("#"):
                continue
            if not (f.parent / m.split("#")[0]).exists():
                bad.append(f"{f.name} -> {m}")
    assert bad == []


def test_svgs_parse_and_are_self_contained():
    svgs = list(ROOT.rglob("*.svg"))
    assert len(svgs) >= 20
    for p in svgs:
        if ".git/" in str(p):
            continue
        ET.parse(p)
        t = p.read_text().replace("http://www.w3.org/2000/svg", "")
        assert "http" not in t and "@import" not in t and "<image" not in t, p


def test_every_svg_has_png_with_magic_bytes():
    for p in (ROOT / "docs" / "assets").rglob("*.svg"):
        png = p.with_suffix(".png")
        assert png.exists() and png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n", png
    assert (ROOT / "assets" / "logo.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def _png_size(p):
    d = p.read_bytes()
    return struct.unpack(">II", d[16:24])


def test_brand_kit_dimensions():
    assert _png_size(ROOT / "docs/assets/logo.png") == (1200, 360)
    assert _png_size(ROOT / "assets/logo.png") == (512, 512)
    assert _png_size(ROOT / "docs/assets/icon.png") == (512, 512)
    for n in ("scanners", "normalize", "score", "report", "mcp", "remediate", "ci", "dynamic"):
        assert (ROOT / f"docs/assets/icons/icon-{n}.svg").exists()


def test_icon_legibility_gate_stroke_width():
    """Square icon: every stroke >= 12 in the 512 viewBox; category icons >= 2 in 64 viewBox."""
    for rel, minimum in (("assets/logo.svg", 12), ("docs/assets/icon.svg", 12)):
        widths = [float(w) for w in re.findall(r'stroke-width="([\d.]+)"', (ROOT / rel).read_text())]
        assert widths and min(widths) >= minimum, rel
    for p in (ROOT / "docs/assets/icons").glob("*.svg"):
        widths = [float(w) for w in re.findall(r'stroke-width="([\d.]+)"', p.read_text())]
        assert widths and min(widths) >= 2, p
    # square icon contains no text
    assert "<text" not in (ROOT / "assets/logo.svg").read_text()


def test_png_icon_legible_at_32px():
    import shutil
    if not shutil.which("convert"):
        pytest.skip("ImageMagick not installed")
    r = subprocess.run(["convert", str(ROOT / "assets/logo.png"), "-resize", "32x32", "-format", "%[fx:mean] %[fx:standard_deviation]", "info:"],
                       capture_output=True, text=True)
    mean, sd = map(float, r.stdout.split())
    assert sd > 0.05, "icon collapses to a flat colour at 32px"


def test_generator_is_deterministic(tmp_path):
    outs = []
    for i in (1, 2):
        d = tmp_path / str(i)
        subprocess.run([sys.executable, str(ROOT / "scripts/render-graphics.py"), "--root", str(d), "--no-png"], check=True, capture_output=True)
        outs.append(d)
    a = {p.relative_to(outs[0]): p.read_bytes() for p in outs[0].rglob("*") if p.is_file()}
    b = {p.relative_to(outs[1]): p.read_bytes() for p in outs[1].rglob("*") if p.is_file()}
    assert a == b and len(a) > 20


def test_generated_files_match_committed(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "scripts/render-graphics.py"), "--root", str(tmp_path), "--no-png"], check=True, capture_output=True)
    stale = [str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if p.is_file()
             and (not (ROOT / p.relative_to(tmp_path)).exists() or (ROOT / p.relative_to(tmp_path)).read_bytes() != p.read_bytes())]
    assert stale == [], f"stale generated files; run scripts/render-graphics.py: {stale}"


def test_counts_derived_from_catalog():
    data = json.loads((ROOT / "docs/data.json").read_text())
    assert data["counts"] == catalog.counts()
    assert data["version"] == kaleidoscan.__version__
    c = catalog.counts()
    assert len(set(s[0] for s in catalog.SCANNERS)) == c["scanners"]
    assert c["views"] == 10 and c["stages"] == 11  # spec scanners.md s4 / pipeline


def test_readme_and_docs_counts_match():
    c = catalog.counts()
    readme = (ROOT / "README.md").read_text()
    assert f"{c['scanners']} scanner" in readme and f"{c['views']} views" in readme
    assert f"{c['stages']} pipeline stages" in readme
    idx = (ROOT / "docs/index.html").read_text()
    assert f"<b>{c['scanners']}</b>" in idx and f"<b>{c['views']}</b>" in idx
    # any "N scanners" / "N views" claim in prose must equal the catalog
    for f in MD:
        t = f.read_text()
        for n in re.findall(r"\b(\d+) (?:planned )?scanners\b", t):
            assert int(n) in (c["scanners"], c["scanners_baseline"], c["scanners_tier_a"], c["scanners_restricted"]), (f, n)
        for n in re.findall(r"\b(\d+) views\b", t):
            assert int(n) == c["views"], (f, n)


def test_version_parity():
    v = kaleidoscan.__version__
    assert f'version-{v}' in (ROOT / "README.md").read_text()
    assert f"v{v}" in (ROOT / "docs/index.html").read_text()
    assert f"v{v}" in (ROOT / "docs/assets/logo.svg").read_text()
    assert f"## {v}" in (ROOT / "docs/CHANGELOG.md").read_text()


def test_pages_meta_and_shell():
    idx = (ROOT / "docs/index.html").read_text()
    for needle in ('property="og:title"', 'property="og:description"', 'property="og:image" content="assets/logo.png"',
                   'rel="icon" type="image/svg+xml" href="assets/icon.svg"', 'name="viewport"', "prefers-reduced-motion"):
        assert needle in idx, needle
    assert not re.search(r"<script[^>]+src=|<link[^>]+stylesheet", idx)
    assert (ROOT / "docs/.nojekyll").exists()


def test_pages_workflow_hardened():
    wf = (ROOT / ".github/workflows/pages.yml").read_text()
    uses = re.findall(r"uses:\s*(\S+)", wf)
    assert uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses), uses
    assert re.search(r"^permissions:\s*\n\s+contents: read", wf, re.M)
    assert "pages: write" in wf and "id-token: write" in wf
    assert "pull_request_target" not in wf and "secrets." not in wf


def test_no_machine_paths_or_personal_data():
    bad = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or ".git" in p.parts or p.suffix in (".png",) or "__pycache__" in p.parts or p.name == "test_docs.py":
            continue
        t = p.read_text(errors="ignore")
        if re.search(r"/home/\w+|/Users/\w+|git@github|@gmail\.com", t):
            bad.append(str(p.relative_to(ROOT)))
    assert bad == []


def _mermaid_blocks():
    for f in MD:
        for m in re.findall(r"```mermaid\n(.*?)```", f.read_text(), re.S):
            yield f, m


def test_mermaid_blocks_wellformed():
    blocks = list(_mermaid_blocks())
    assert len(blocks) >= 5
    kinds = ("flowchart", "graph", "sequenceDiagram", "stateDiagram-v2", "classDiagram", "erDiagram", "gantt")
    for f, b in blocks:
        assert b.strip().split()[0] in kinds, (f, b[:30])
        for o, c in ("[]", "()", "{}"):
            assert b.count(o) == b.count(c), (f, o)
        assert b.count('"') % 2 == 0, f


def _doc_commands():
    """Every `kaleidoscan <sub>` / `kscan <sub>` at the start of a fenced-code line or inline code in docs."""
    found = set()
    for f in MD:
        t = f.read_text()
        for blk in re.findall(r"```(?:bash|sh|console|text)?\n(.*?)```", t, re.S):
            for line in blk.splitlines():
                line = line.strip().lstrip("$ ").strip()
                m = re.match(r"(?:kaleidoscan|kscan)\s+([a-z][a-z-]*)", line)
                if m:
                    found.add((f.name, m.group(1)))
        for m in re.findall(r"`(?:kaleidoscan|kscan) ([a-z][a-z-]*)", t):
            found.add((f.name, m))
    return found


def test_every_documented_command_exists_in_catalog():
    names = {n for n, _ in catalog.COMMANDS}
    unknown = [(f, c) for f, c in _doc_commands() if c not in names]
    assert unknown == []


def test_implemented_commands_documented_and_runnable():
    impl = [n for n, s in catalog.COMMANDS if s == "implemented"]
    cli_ref = (ROOT / "docs/running.md").read_text()
    for n in impl:
        assert f"`kaleidoscan {n}" in cli_ref, n
        r = subprocess.run([sys.executable, "-m", "kaleidoscan", n, "--help"], capture_output=True, text=True)
        assert r.returncode == 0, n
    # the CLI really exposes exactly the implemented set
    helptxt = subprocess.run([sys.executable, "-m", "kaleidoscan", "--help"], capture_output=True, text=True).stdout
    for n, s in catalog.COMMANDS:
        assert (n in helptxt.split("COMMAND")[-1] if s == "implemented" else True), n


def test_planned_commands_marked_planned_in_cli_reference():
    ref = (ROOT / "docs/running.md").read_text()
    for n, s in catalog.COMMANDS:
        if s == "planned":
            row = [l for l in ref.splitlines() if f"`kaleidoscan {n}" in l]
            assert row and all("planned" in l.lower() for l in row), n


def test_doc_examples_actually_run(tmp_path):
    """The README/how-to quickstart commands that are implemented are executed for real."""
    out = tmp_path / "v.html"
    r = subprocess.run([sys.executable, "-m", "kaleidoscan", "viz", "--sample", "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0 and out.exists()
    r = subprocess.run([sys.executable, "-m", "kaleidoscan", "doctor", "--json"], capture_output=True, text=True)
    assert json.loads(r.stdout)["schema"] == "kaleidoscan.doctor/1"


def test_exit_codes_table_matches_catalog():
    ref = (ROOT / "docs/running.md").read_text()
    for code, desc in catalog.EXIT_CODES:
        assert re.search(rf"\|\s*{code}\s*\|", ref), code


def test_every_graphic_embedded_somewhere():
    corpus = "".join(f.read_text() for f in MD) + (ROOT / "docs/index.html").read_text()
    for svg in (ROOT / "docs/assets/examples").glob("*.svg"):
        assert svg.name in corpus, f"orphaned graphic {svg.name}"


def test_images_have_alt_text():
    for f in MD:
        for alt in re.findall(r"!\[([^\]]*)\]\(", f.read_text()):
            assert alt.strip(), f


def test_visualizer_linked_from_docs_and_pages():
    assert "examples/visualizer.html" in (ROOT / "docs/index.html").read_text()
    assert "visualizer.md" in (ROOT / "docs/README.md").read_text()
    assert "examples/visualizer.html" in (ROOT / "README.md").read_text().replace("docs/examples/visualizer.html", "examples/visualizer.html")
