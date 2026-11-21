"""T-DOC: the Pages site build. No network."""
import hashlib
import importlib.util
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_site", ROOT / "scripts" / "build-site.py")
bs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bs)


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    out = tmp_path_factory.mktemp("site")
    bs.build(ROOT / "docs", out)
    return out


def _digest(d: Path):
    return {p.relative_to(d).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.rglob("*")) if p.is_file()}


def test_every_md_becomes_html_and_no_md_published(site):
    assert not list(site.rglob("*.md"))
    for md in (ROOT / "docs").rglob("*.md"):
        assert (site / md.relative_to(ROOT / "docs").with_suffix(".html")).is_file()
    assert (site / "usermanual" / "index.html").is_file() and (site / "404.html").is_file()


def test_no_md_hrefs_and_internal_links_resolve(site):
    bad = []
    for f in site.rglob("*.html"):
        if f.name == "404.html":
            continue
        text = f.read_text()
        for u in re.findall(r'(?:href|src)="([^"]+)"', text):
            if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", u) or u.startswith("#"):
                continue
            path = u.split("#")[0].split("?")[0]
            if path.lower().endswith(".md"):
                bad.append(f"{f.relative_to(site)} -> .md link {u}")
            elif path and not (f.parent / path).resolve().exists():
                bad.append(f"{f.relative_to(site)} -> missing {u}")
    assert bad == []


def test_anchors_kept_and_mermaid_no_cdn(site):
    assert "mermaid" in (site / "architecture.html").read_text()
    for f in site.rglob("*.html"):
        t = f.read_text()
        assert "cdn." not in t and "unpkg" not in t and "jsdelivr" not in t or f.name == "visualizer.html"
    assert 'class="mermaid-src"' in (site / "architecture.html").read_text()
    assert 'href="../running.html"' in (site / "usermanual" / "README.html").read_text()


def test_deterministic(site, tmp_path):
    bs.build(ROOT / "docs", tmp_path / "again")
    assert _digest(site) == _digest(tmp_path / "again")


def test_sources_unmodified_and_workflow_uploads_built_dir():
    wf = (ROOT / ".github" / "workflows" / "pages.yml").read_text()
    assert "build-site.py" in wf and "path: _site" in wf and "path: docs" not in wf
    assert "_site/" in (ROOT / ".gitignore").read_text()
    assert not re.search(r'href="[^"#]*\.md(#[^"]*)?"', (ROOT / "docs" / "index.html").read_text())
