# Configuration: `kaleidoscan.yaml` (C4)

Status: **planned** (Task 1). This is the contract the loader will validate with pydantic; unknown keys are rejected.

```yaml
version: 1
name: default
target: {path: ".", exclude: ["**/node_modules/**", "**/.venv/**"]}
scanners:                       # order irrelevant; run in parallel (max_parallel)
  - {id: flowscope, enabled: true}
  - {id: semgrep,   enabled: true, config: {rules: ["p/ci"], offline_rules: "./rules"}}
  - {id: bandit,    enabled: true}
  - {id: gitleaks,  enabled: true}
dynamic: null                   # RESERVED: non-null is an error ("dynamic testing not implemented")
policy:
  fail_on: {severity_at_least: high, new_only: true, baseline: "baseline.sarif"}
  require_scanners: [flowscope]  # missing or error => gate fails (exit 3)
  suppressions: "./.kaleidoscan-ignore.yaml"   # entries: fingerprint, reason, expires
reports: [sarif, html, markdown, junit, json]
limits: {timeout_s: 600, max_output_mb: 64, max_parallel: 4}
```

| Key | Meaning |
|---|---|
| `version` | schema version, currently 1 |
| `target.path`, `target.exclude` | what to scan; relative paths resolved against the config file |
| `scanners[]` | `id` from [scanners.md](scanners.md), `enabled`, scanner-specific `config` |
| `policy.fail_on` | severity threshold, `new_only` against a SARIF `baseline` |
| `policy.require_scanners` | scanners that must run OK |
| `policy.suppressions` | file of `{fingerprint, reason, expires}`; expired entries stop suppressing |
| `reports` | output formats |
| `limits` | per-scanner timeout, output cap, parallelism |

Profiles: `--profile fast|full|ci` override the above. Severity mapping (C6): SARIF `security-severity` >= 9.0 critical,
>= 7.0 high, >= 4.0 medium, > 0 low; otherwise error=high, warning=medium, note=low, none=info; unknown maps to medium with
`confidence: unknown`.
