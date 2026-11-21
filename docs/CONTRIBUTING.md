# Contributing

- Tests first: write failing tests, implement minimally, run `scripts/verify.sh --tier <tier>`.
- Tiers: `smoke`, `unit`, `integration`, `system`, `security` (+ `perf`, `stress`, `torture`). Mark each test module or test with its tier.
- Never use `shell=True` or `os.system` (an AST test enforces it). Subprocesses take argv lists.
- Documented counts live in `kaleidoscan/catalog.py`. After changing it (or any graphic code) run `python3 scripts/render-graphics.py`;
  `tests/test_docs.py` fails when generated files are stale, links break, a command is documented that does not exist, or versions differ.
- Keep build output, venvs and caches under `/datanapps`, not `/tmp`.
- Local commits only until a maintainer decides to publish.
