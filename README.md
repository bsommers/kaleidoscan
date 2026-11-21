<p align="center"><img src="docs/assets/logo.svg" alt="kaleidoscan hero banner: many scanners, one ranked result" width="100%"></p>

![version](https://img.shields.io/badge/version-0.1.0-00e5ff) ![python](https://img.shields.io/badge/python-%3E%3D3.11-38bdf8) ![status](https://img.shields.io/badge/status-early%20development-ffb800)

**kaleidoscan** runs several security scanners over one target, normalizes every result to SARIF 2.1.0 plus a small
run envelope, ranks findings by *measured* scanner reliability (not by counting tools), and gates the result in local or
remote CI. The same capabilities are meant to be exposed through a CLI, a Python API, an HTTP facade, an MCP server and
a CI action. Dynamic testing (DAST) is a reserved placeholder only.

> **Status (honest):** this is early development. Implemented today: `kaleidoscan doctor` (tool availability) and
> `kaleidoscan viz` (offline pipeline visualizer). Everything else in the docs is the **planned** design from the spec and is
> labelled "planned" wherever a command or adapter is described. See [docs/running.md](docs/running.md) for the exact status table.

The project is generated and checked so that documented counts cannot drift: 16 scanner adapters in the portfolio
(all planned), 10 views and 11 pipeline stages, derived from `kaleidoscan/catalog.py` (see [docs/scanners.md](docs/scanners.md)).

## Visual showcase

| | |
|---|---|
| ![System architecture: five surfaces over a surface-agnostic core over scanner adapters](docs/assets/examples/architecture-overview.svg) | ![Pipeline data flow through eleven stages from target to pull request](docs/assets/examples/pipeline-dataflow.svg) |
| Architecture: surfaces, core, adapters | Data flow through 11 pipeline stages |
| ![Noisy-OR finding score with a worked example](docs/assets/examples/scoring-explainer.svg) | ![Scan, review, plan, remediate with revert loop, and a human-gated PR](docs/assets/examples/remediation-flow.svg) |
| Ranking: noisy-OR over independent scanners | Remediation with a verify-and-revert loop and human gate |

![Visualizer: stage strip, scanner fan-out and per-run panels from a sample run](docs/assets/examples/visualizer-overview.svg)

More graphics: scanner portfolio, views, MCP forge pipeline, CI topology and trust boundaries are embedded in
[docs/architecture.md](docs/architecture.md) and [docs/integrations.md](docs/integrations.md). Benchmark charts and real
report screenshots are placeholders until Task 13 (benchmark) and Task 9 (reporters) land.

## Quickstart

```bash
uv tool install .                 # or: uv sync && uv run kaleidoscan ...
kaleidoscan doctor                # which scanners are installed, and their versions
kaleidoscan viz --sample --out visualizer.html   # offline pipeline visualizer on the bundled sample run
```

Open the sample visualizer: [docs/examples/visualizer.html](docs/examples/visualizer.html) (self-contained, no network).
The `kscan` alias is installed alongside `kaleidoscan`.

## Documentation

Start at the [docs hub](docs/README.md) or the [user manual](docs/usermanual/README.md).
[Purpose](docs/purpose.md) · [Architecture](docs/architecture.md) · [Running and CLI reference](docs/running.md) ·
[Configuration](docs/configuration.md) · [How-to](docs/how-to.md) · [Scanners](docs/scanners.md) ·
[Views and scoring](docs/views-and-scoring.md) · [Remediation](docs/remediation.md) · [HTTP, MCP and CI](docs/integrations.md) ·
[Visualizer](docs/visualizer.md) · [Contributing](docs/CONTRIBUTING.md) · [Changelog](docs/CHANGELOG.md).
The GitHub Pages site lives in [docs/index.html](docs/index.html) (not yet published).

## Verify

```bash
scripts/verify.sh              # smoke, unit, integration, system, security tiers; prints PASS/SKIP/FAIL per tier
scripts/verify.sh --tier unit
python3 scripts/render-graphics.py   # regenerate graphics, docs/scanners.md, docs/data.json and the Pages shell
```

Build output, virtualenvs and caches default to `/datanapps` (see `scripts/verify.sh`) and never to `/tmp`.

## License

MIT, see [LICENSE](LICENSE).
