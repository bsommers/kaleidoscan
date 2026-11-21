# Contributing

- Tests first: write failing tests, implement minimally, run `scripts/verify.sh --tier <tier>`.
- Tiers: `smoke`, `unit`, `integration`, `system`, `security` (+ `perf`, `stress`, `torture`). Mark each test module or test with its tier.
- Never use `shell=True` or `os.system` (an AST test enforces it). Subprocesses take argv lists.
- Documented counts live in `kaleidoscan/catalog.py`. After changing it (or any graphic code) run `python3 scripts/render-graphics.py`;
  `tests/test_docs.py` fails when generated files are stale, links break, a command is documented that does not exist, or versions differ.
- GitHub Pages site: `uv run python scripts/build-site.py [--out _site]` converts every `docs/**/*.md` to themed `.html` (intra-doc `.md` links rewritten to `.html`, anchors kept, mermaid blocks shown as code with a link to the pre-rendered SVG, `404.html` redirects old `.md` URLs). Sources stay untouched so links work on GitHub. `.github/workflows/pages.yml` runs it and uploads `_site/`. Never link to `.md` from `docs/index.html`; `tests/test_site.py` enforces it.
- Keep build output, venvs and caches under `/datanapps`, not `/tmp`.
- Local commits only until a maintainer decides to publish.
