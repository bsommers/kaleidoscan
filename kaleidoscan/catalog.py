"""Single source for documented counts: scanner portfolio, views, commands, pipeline stages.

Docs, graphics and the Pages site are generated from / checked against this module (T-DOC),
so numbers cannot drift. Status values: "planned" (spec only) or "implemented" (code + tests exist).
Scanner `tier` follows spec/scanners.md: baseline (Synth/Flowscope parity), A, B, C.
"""
from __future__ import annotations

# (id, display name, kind, languages, license, restricted, tier)
SCANNERS: tuple[tuple[str, str, str, tuple[str, ...], str, bool, str], ...] = (
    ("flowscope", "Flowscope", "sast", ("python", "javascript", "typescript", "go"), "see upstream", False, "baseline"),
    ("semgrep", "Semgrep CE", "sast", ("python", "go", "java", "csharp"), "LGPL-2.1 (rule packs vary)", False, "baseline"),
    ("bandit", "Bandit", "sast", ("python",), "Apache-2.0", False, "baseline"),
    ("gosec", "gosec", "sast", ("go",), "Apache-2.0", False, "baseline"),
    ("flawfinder", "flawfinder", "sast", ("c",), "GPL-2.0", False, "baseline"),
    ("bearer", "Bearer CLI", "sast", ("python", "javascript", "typescript", "ruby", "java", "php", "go"), "see upstream", False, "baseline"),
    ("codeql", "CodeQL", "sast", ("c", "cpp", "java", "python", "csharp"), "proprietary-restricted", True, "baseline"),
    ("ghidra-angr", "Ghidra / angr (binary)", "sast", ("binary",), "Apache-2.0 / BSD-2", False, "baseline"),
    ("opengrep", "Opengrep", "sast", ("*",), "LGPL-2.1", False, "A"),
    ("brakeman", "Brakeman", "sast", ("ruby",), "see upstream", False, "A"),
    ("cppcheck", "cppcheck", "sast", ("c", "cpp"), "GPL-3.0", False, "A"),
    ("gitleaks", "Gitleaks", "secrets", ("*",), "MIT", False, "A"),
    ("osv-scanner", "OSV-Scanner", "sca", ("*",), "Apache-2.0", False, "A"),
    ("trivy", "Trivy (pinned)", "sca", ("*",), "Apache-2.0", False, "A"),
    ("checkov", "Checkov", "iac", ("terraform", "kubernetes", "docker"), "Apache-2.0", False, "A"),
    ("kics", "KICS", "iac", ("terraform", "kubernetes", "docker"), "Apache-2.0", False, "A"),
)

# Views from spec/scanners.md section 4 (exactly ten rows, taxonomy rollups kept as separate views).
VIEWS: tuple[tuple[str, str], ...] = (
    ("by-scanner", "each scanner's normalized results side by side"),
    ("consensus", "reported by >= k independent scanners"),
    ("unique", "found by exactly one scanner"),
    ("disagreement", "same location, different CWE/severity across scanners"),
    ("by-taxonomy", "by-cwe / by-owasp / by-file / by-language rollups"),
    ("by-category", "sast / sca / secrets / iac / container (dynamic reserved)"),
    ("ranked", "ordered by finding score with explanation"),
    ("new-vs-baseline", "PR / diff mode"),
    ("taint-flows", "only findings carrying codeFlows"),
    ("coverage", "language / CWE x scanner matrix incl. gaps"),
)

# (command, status). Implemented commands are exercised by doc-example tests.
COMMANDS: tuple[tuple[str, str], ...] = (
    ("doctor", "implemented"), ("viz", "implemented"),
    ("scanners", "planned"), ("run", "planned"), ("show", "planned"), ("findings", "planned"),
    ("report", "planned"), ("diff", "planned"), ("gate", "planned"), ("serve", "planned"),
    ("select", "planned"), ("bench", "planned"), ("review", "planned"), ("plan", "planned"),
    ("remediate", "planned"), ("open-pr", "planned"), ("fix", "planned"), ("gaps", "planned"),
)

# Pipeline stages in order (spec section 3 + remediation.md).
STAGES: tuple[tuple[str, str, str], ...] = (
    ("target", "Target", "repo / dir / image under an allowed root"),
    ("scan", "Scan", "adapters run in parallel (argv-only, timeout, output cap)"),
    ("normalize", "Normalize + dedup", "SARIF -> C2 findings, cwe+path+/-3 lines"),
    ("score", "Score + rank", "noisy-OR over independent scanners"),
    ("views", "Views", "consensus / unique / disagreement / taint-flows"),
    ("gate", "Gate", "fail_on, baseline, suppressions, require_scanners"),
    ("reports", "Reports", "sarif, html, markdown, junit, json"),
    ("review", "Review", "deterministic checks + evidence-validated AI"),
    ("plan", "Plan", "deterministic / ai / manual strategies"),
    ("remediate", "Remediate", "isolated worktree, verify, revert-on-fail"),
    ("pr", "Pull request", "dry-run default, human-confirmed publish"),
)

EXIT_CODES: tuple[tuple[int, str], ...] = (
    (0, "gate passed / success"), (1, "gate failed (findings or policy)"),
    (2, "usage or config error"), (3, "required scanner missing or failed"), (4, "internal error"),
)


def counts() -> dict[str, int]:
    return {
        "scanners": len(SCANNERS),
        "scanners_baseline": sum(1 for s in SCANNERS if s[6] == "baseline"),
        "scanners_tier_a": sum(1 for s in SCANNERS if s[6] == "A"),
        "scanners_restricted": sum(1 for s in SCANNERS if s[5]),
        "views": len(VIEWS),
        "commands": len(COMMANDS),
        "commands_implemented": sum(1 for c in COMMANDS if c[1] == "implemented"),
        "stages": len(STAGES),
    }
