#!/usr/bin/env python3
"""Deterministic GitHub Pages build: docs/ -> site dir (default _site, gitignored).

Every docs/**/*.md becomes .html in the neon theme with a nav bar. Relative .md links are
rewritten to .html (anchors kept); images/assets/other files are copied unchanged; the .md
sources are NOT published (Pages would serve them as text/markdown) and are never modified.
```mermaid blocks render as styled code plus a link to the nearest following pre-rendered
SVG diagram of the same page (no CDN, no JavaScript renderer). 404.html redirects old
*.md URLs to the .html page. Requires `markdown` (pinned in pyproject dev group).
No timestamps, no network: running twice yields byte-identical output.
Usage: build-site.py [--docs DIR] [--out DIR]
"""
from __future__ import annotations

import argparse
import posixpath
import re
import shutil
import sys
from html import escape
from pathlib import Path

try:
    import markdown
except ImportError:  # pragma: no cover
    sys.exit("build-site.py needs the 'markdown' package: uv run python scripts/build-site.py")

REPO = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/bsommers/kaleidoscan"
NAV = [("Home", "index.html"), ("Purpose", "purpose.html"), ("Architecture", "architecture.html"), ("Running", "running.html"),
       ("Configuration", "configuration.html"), ("How-to", "how-to.html"), ("Scanners", "scanners.html"),
       ("Scoring", "views-and-scoring.html"), ("Remediation", "remediation.html"), ("Integrations", "integrations.html"),
       ("Visualizer", "visualizer.html"), ("User manual", "usermanual/README.html"), ("Contributing", "CONTRIBUTING.html"),
       ("Changelog", "CHANGELOG.html")]
CSS = """:root{--bg:#050811;--cy:#00e5ff;--sky:#38bdf8;--txt:#f0f6fc;--mut:#94a3b8;--panel:#0b1326}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:16px/1.6 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
nav{background:var(--panel);border-bottom:1.5px solid var(--cy);padding:8px 16px;display:flex;flex-wrap:wrap;gap:6px 14px}
nav a{color:var(--sky);text-decoration:none;font-size:.9rem}nav a:hover,nav a[aria-current]{color:var(--cy);text-decoration:underline}
main{max-width:980px;margin:0 auto;padding:16px}a{color:var(--sky)}h1,h2,h3,h4{font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--cy)}
img{max-width:100%;height:auto;border:1px solid var(--sky);border-radius:8px;background:var(--panel)}
pre{background:#070d1c;border:1px solid var(--sky);border-radius:8px;padding:10px;overflow-x:auto;color:#5eead4}
code{font-family:ui-monospace,Menlo,Consolas,monospace;color:#5eead4}p code,li code,td code{background:#070d1c;padding:1px 5px;border-radius:4px}
table{border-collapse:collapse;display:block;overflow-x:auto}th,td{text-align:left;padding:4px 10px;border:1px solid rgba(56,189,248,.35)}
blockquote{border-left:3px solid var(--cy);margin:0;padding:0 14px;color:var(--mut)}hr{border:0;border-top:1px solid rgba(56,189,248,.35)}
.mermaid-src{border:1px dashed var(--sky);border-radius:8px;padding:6px 10px;margin:12px 0}.mermaid-src>span{color:var(--mut);font-size:.85rem}
footer{max-width:980px;margin:0 auto;padding:16px;color:var(--mut);font-size:.85rem}"""
LINK = re.compile(r'(<a\s[^>]*?href=")([^"]+)(")')
IMG = re.compile(r'<img\s[^>]*?src="([^"]+)"')
MERMAID = re.compile(r'<pre><code class="language-mermaid">(.*?)</code></pre>', re.S)


def is_local(u: str) -> bool:
    return not (re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", u) or u.startswith(("#", "//", "/")))


def md_to_html_href(u: str) -> str:
    if not is_local(u):
        return u
    path, sep, frag = u.partition("#")
    if path.lower().endswith(".md"):
        path = path[:-3] + ".html"
    return path + sep + frag


def render_page(md_path: Path, rel: str) -> str:
    text = md_path.read_text(encoding="utf-8")
    body = markdown.Markdown(extensions=["fenced_code", "tables", "toc", "sane_lists"], output_format="html").convert(text)
    body = LINK.sub(lambda m: m.group(1) + md_to_html_href(m.group(2)) + m.group(3), body)

    def mer(m: re.Match) -> str:
        after = body[m.end():]
        im = IMG.search(after)
        link = ""
        if im and is_local(im.group(1)) and im.group(1).endswith(".svg"):
            link = f' <a href="{im.group(1)}">view the rendered diagram</a>'
        return (f'<div class="mermaid-src"><span>Diagram source (mermaid).{link}</span>'
                f'<pre><code class="language-mermaid">{m.group(1)}</code></pre></div>')

    body = MERMAID.sub(mer, body)
    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", body, re.S)
    title = re.sub(r"<[^>]+>", "", h1.group(1)) if h1 else md_path.stem
    depth = rel.count("/")
    up = "../" * depth
    cur = md_to_html_href(rel)
    nav = "".join(f'<a href="{up}{h}"' + (' aria-current="page"' if h == cur else "") + f">{escape(t)}</a>" for t, h in NAV)
    nav += f'<a href="{REPO_URL}">GitHub</a>'
    return (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f'<title>{escape(title)} - kaleidoscan</title>\n<link rel="icon" type="image/svg+xml" href="{up}assets/icon.svg">\n'
            f"<style>{CSS}</style></head><body>\n<nav>{nav}</nav>\n<main>\n{body}\n</main>\n"
            f'<footer>Rendered from <a href="{REPO_URL}/blob/main/docs/{rel}">docs/{escape(rel)}</a></footer>\n</body></html>\n')


NOT_FOUND = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Not found - kaleidoscan</title>
<style>body{background:#050811;color:#f0f6fc;font:16px/1.6 system-ui,sans-serif;padding:24px}a{color:#38bdf8}</style></head><body>
<h1 style="color:#00e5ff">Page not found</h1>
<p id="m">Try the <a href="/kaleidoscan/">home page</a>.</p>
<script>(function(){var p=location.pathname;if(/\\.md$/i.test(p)){location.replace(p.replace(/\\.md$/i,'.html')+location.search+location.hash)}
else if(/\\/$/.test(p)&&p!=='/'){location.replace(p+'README.html'+location.search+location.hash)}})();</script>
<noscript><p>Old .md links moved to .html: replace the extension.</p></noscript></body></html>
"""


def build(docs: Path, out: Path) -> list[str]:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    written = []
    for src in sorted(docs.rglob("*")):
        if not src.is_file() or "__pycache__" in src.parts:
            continue
        rel = src.relative_to(docs).as_posix()
        if src.suffix.lower() == ".md":
            dest = out / (rel[:-3] + ".html")
            dest.parent.mkdir(parents=True, exist_ok=True)
            html = render_page(src, rel)
            dest.write_text(html, encoding="utf-8")
            written.append(dest.relative_to(out).as_posix())
            if rel != "README.md" and src.name == "README.md":  # directory URL -> index.html
                (dest.parent / "index.html").write_text(html, encoding="utf-8")
        else:
            dest = out / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            written.append(rel)
    (out / "404.html").write_text(NOT_FOUND, encoding="utf-8")
    (out / ".nojekyll").touch()
    return sorted(written)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--docs", type=Path, default=REPO / "docs")
    ap.add_argument("--out", type=Path, default=REPO / "_site")
    a = ap.parse_args(argv)
    files = build(a.docs, a.out)
    print(f"built {len(files)} files into {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
