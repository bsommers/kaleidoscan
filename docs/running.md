# Running

## Install

```bash
uv tool install .         # installs kaleidoscan and kscan
uv sync                   # or work in a project venv (set UV_PROJECT_ENVIRONMENT to keep it off the repo)
```

Python >= 3.11. The runtime has no third-party dependencies. In CI use the composite action (planned, see [integrations.md](integrations.md)).

## CLI reference

Status of every command (`planned` = specified in the contracts, not yet in code; the table is checked against `kaleidoscan/catalog.py`):

| Command | Status | Purpose |
|---|---|---|
| `kaleidoscan doctor [--json] [--strict]` | implemented | tool availability and versions; `--strict` exits 3 if a required scanner (flowscope) is missing |
| `kaleidoscan viz [RUN_DIR] [--sample] [--out FILE]` | implemented | offline HTML visualizer for a run envelope ([visualizer.md](visualizer.md)) |
| `kaleidoscan scanners [--json] [--matrix]` | planned | list scanners, availability, language coverage |
| `kaleidoscan run [--config F] [--only ids] [--target P] [--offline] [--out DIR] [--profile fast\|full\|ci]` | planned | run the pipeline |
| `kaleidoscan show RUN` | planned | print a run envelope |
| `kaleidoscan findings RUN [--severity S] [--cwe C] [--scanner ID] [--view V]` | planned | query findings |
| `kaleidoscan report RUN --format html\|md\|junit\|json\|sarif` | planned | render a report |
| `kaleidoscan diff A B` | planned | new / fixed findings between runs |
| `kaleidoscan gate RUN` | planned | policy verdict as an exit code |
| `kaleidoscan serve [--http 127.0.0.1:PORT]` | planned | HTTP facade |
| `kaleidoscan select` | planned | choose complementary scanners with `--explain` |
| `kaleidoscan bench` | planned | benchmark scanners, write score file |
| `kaleidoscan review` | planned | review findings or a PR |
| `kaleidoscan plan` | planned | remediation plan |
| `kaleidoscan remediate` | planned | apply plan in an isolated worktree |
| `kaleidoscan open-pr` | planned | PR dry-run, gated publish |
| `kaleidoscan fix` | planned | scan, review, plan, remediate, PR in one go |
| `kaleidoscan gaps` | planned | report language gaps in scanners |

Global flag: `--version`. With `--json`, stdout carries only JSON and logs go to stderr.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | gate passed / success |
| 1 | gate failed (findings or policy) |
| 2 | usage or config error |
| 3 | required scanner missing or failed |
| 4 | internal error |

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `FLOWSCOPE_BIN` | doctor (implemented), adapter (planned) | explicit path to the flowscope binary, wins over PATH |
| `KALEIDOSCAN_ALLOWED_ROOTS` | HTTP/MCP (planned) | roots a target must live under |
| `KALEIDOSCAN_TOKEN` | HTTP (planned) | optional bearer token |
| `UV_PROJECT_ENVIRONMENT`, `UV_CACHE_DIR`, `KALEIDOSCAN_CACHE` | `scripts/verify.sh` | venv and cache locations (default under `/datanapps`) |

## Verification tiers

`scripts/verify.sh` runs `smoke`, `unit`, `integration`, `system`, `security` (and `perf`, `stress`, `torture` with `--all`).
Output: `<tier>: PASS n / SKIP m / FAIL k`, followed by every skip reason. A skip never counts as green silently.

## Documentation site

`uv run python scripts/build-site.py --out _site` builds the Pages site locally (needs the pinned dev dependency `markdown`); open `_site/index.html`. See [CONTRIBUTING.md](CONTRIBUTING.md).
