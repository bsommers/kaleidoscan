# Architecture

![System architecture: five surfaces over a surface-agnostic core over scanner adapters](assets/examples/architecture-overview.svg)

Layers (status: **planned** except the CLI shell, `doctor` and `viz`):

```mermaid
flowchart TD
  subgraph Surfaces
    CLI[CLI kaleidoscan / kscan]
    API[Python API]
    HTTP[HTTP loopback]
    MCP[MCP server]
    CIA[CI action]
  end
  subgraph Core
    CFG[config C4] --> RUN[runner]
    RUN --> NORM[normalize C2]
    NORM --> SCORE[scoring]
    SCORE --> VIEWS[views]
    VIEWS --> GATE[policy gate]
    GATE --> REP[reports]
  end
  subgraph Adapters
    A1[adapter per scanner C1]
  end
  CLI --> CFG
  API --> CFG
  HTTP --> CFG
  MCP --> HTTP
  CIA --> CLI
  RUN --> A1
```

## Adapter model (C1)

Every scanner is one file implementing `Adapter` (`detect`, `applicable`, `run`) plus a registry line and a fixture-based
test; the core never changes. A run returns a `ScannerResult` with status `ok | empty | skipped | error | timeout`.
Registry: entry-point group `kaleidoscan.adapters`.

## Data flow

![Pipeline data flow through eleven stages from target to pull request](assets/examples/pipeline-dataflow.svg)

```mermaid
sequenceDiagram
  participant U as User or CI
  participant R as Runner
  participant S as Scanners
  participant N as Normalizer
  participant G as Gate
  U->>R: run with config
  R->>S: argv-only, parallel, timeout
  S-->>R: raw output
  R->>N: SARIF per scanner
  N->>N: merge, dedup, score, views
  N->>G: findings
  G-->>U: exit code 0 to 4 and run dir
```

A run directory holds `summary.json` (envelope C3), merged canonical `results.sarif`, `raw/`, and the reports.
Writes are atomic (temp dir, then rename). Only `summary.json` carries timestamps, so the SARIF and HTML are byte-reproducible.

## Scanner portfolio

![Scanner portfolio table generated from the catalog](assets/examples/scanner-portfolio.svg)

Full generated table: [scanners.md](scanners.md).

## Scoring, selection and views

See [views-and-scoring.md](views-and-scoring.md). Remediation: [remediation.md](remediation.md). Surfaces: [integrations.md](integrations.md).

## Trust boundaries

![Untrusted inputs, boundary controls and trusted core](assets/examples/trust-boundaries.svg)

Untrusted: target contents, scanner output, PR text, MCP requests. Controls sit at the boundary; the core assumes validated data.

## What exists in code today

```mermaid
flowchart LR
  CLI[cli.py] --> D[doctor.py]
  CLI --> V[viz.py]
  V --> S[data/sample-run]
  CAT[catalog.py] --> GEN[scripts/render-graphics.py]
  GEN --> DOCS[docs and Pages]
```

`catalog.py` is the single source for documented counts; `tests/test_docs.py` fails when docs drift from it.
