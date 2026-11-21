"""C6 severity mapping (data-driven). Returns (severity, confidence)."""
from __future__ import annotations

# Per-scanner native-level overrides (lowercased keys).
SCANNER_LEVELS: dict[str, dict[str, str]] = {
    "bandit": {"high": "high", "medium": "medium", "low": "low"},
    "semgrep": {"error": "high", "warning": "medium", "info": "low"},
    "gitleaks": {"error": "high", "warning": "medium", "note": "low"},
}
SARIF_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
# (threshold, severity) descending; security-severity > 0 and below last -> low.
SECURITY_SEVERITY_THRESHOLDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"))


def from_security_severity(score: float) -> str | None:
    for threshold, sev in SECURITY_SEVERITY_THRESHOLDS:
        if score >= threshold:
            return sev
    return "low" if score > 0 else None


def map_severity(
    scanner_id: str,
    level: str | None = None,
    security_severity: object = None,
    native: str | None = None,
) -> tuple[str, str]:
    """Precedence: security-severity > scanner native level > SARIF level > unknown."""
    if security_severity is not None and not isinstance(security_severity, bool):
        try:
            score = float(security_severity)
        except (TypeError, ValueError):
            score = None
        if score is not None and 0 <= score <= 10:
            sev = from_security_severity(score)
            if sev:
                return sev, "high"
    table = SCANNER_LEVELS.get(scanner_id, {})
    for key in (native, level):
        if isinstance(key, str) and key.strip().lower() in table:
            return table[key.strip().lower()], "high"
    if isinstance(level, str) and level.strip().lower() in SARIF_LEVELS:
        return SARIF_LEVELS[level.strip().lower()], "medium"
    return "medium", "unknown"
