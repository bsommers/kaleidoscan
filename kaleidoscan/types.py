"""Core types: C1 (adapter), C2 (normalized finding), C3 (run envelope)."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:  # ScannerConfig lives in config.py (Task 1)
    from kaleidoscan.config import ScannerConfig

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low", "unknown")
ENVELOPE_SCHEMA = "kaleidoscan.run/1"
LINE_BUCKET = 4  # fingerprint bucket width; dedup window is |delta| <= 3
MERGE_LINE_DELTA = 3


class ScannerKind(StrEnum):
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"
    CONTAINER = "container"
    DAST = "dast"


class ScannerStatus(StrEnum):
    OK = "ok"
    EMPTY = "empty"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class ScannerInfo:
    id: str
    kind: ScannerKind
    languages: frozenset[str]
    license: str
    restricted: bool
    offline_capable: bool


@dataclass(frozen=True)
class Target:
    path: Path
    kind: Literal["repo", "dir", "image", "url"]
    languages: frozenset[str]


@dataclass
class ScannerResult:
    scanner_id: str
    status: ScannerStatus
    version: str | None
    files_analyzed: int | None
    sarif: dict | None
    duration_ms: int
    detail: str


class Adapter(Protocol):
    info: ScannerInfo

    def detect(self) -> tuple[bool, str | None]: ...

    def applicable(self, t: Target) -> bool: ...

    def run(self, t: Target, cfg: "ScannerConfig", *, timeout_s: int) -> ScannerResult: ...


@dataclass
class Finding:
    """C2 normalized finding."""

    fingerprint: str
    scanner_ids: list[str]
    rule_ids: dict[str, str]
    cwe: list[str]
    severity: str
    confidence: str
    message: str
    location: dict[str, Any]  # {"path","start_line","end_line"}
    code_flow: list[dict[str, Any]] | None = None
    secret_redacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scanner_ids"] = sorted(set(self.scanner_ids))
        d["cwe"] = sorted(set(self.cwe))
        return d

    def mergeable_with(self, other: "Finding") -> bool:
        """Dedup rule: same cwe set (non-empty) and path, |line delta| <= 3.

        Empty cwe never merges across scanners; same-scanner needs exact fingerprint.
        """
        if self.fingerprint == other.fingerprint:
            return True
        if not self.cwe or not other.cwe:
            return False
        if set(self.cwe) != set(other.cwe):
            return False
        a, b = self.location, other.location
        if a["path"] != b["path"]:
            return False
        return abs(a["start_line"] - b["start_line"]) <= MERGE_LINE_DELTA


def count_severities(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    counts["total"] = len(findings)
    return counts


@dataclass
class RunEnvelope:
    """C3 summary.json."""

    run_id: str
    started_at: str
    finished_at: str
    target: dict[str, Any]
    pipeline: str
    scanners: list[dict[str, Any]]
    findings: list[Finding] = field(default_factory=list)
    gate: dict[str, Any] = field(default_factory=lambda: {"passed": True, "reasons": []})
    schema: str = ENVELOPE_SCHEMA
    dynamic: None = None  # reserved (C9)

    def to_dict(self) -> dict[str, Any]:
        fs = sorted(self.findings, key=lambda f: (f.location["path"], f.location["start_line"], f.fingerprint))
        return {
            "schema": self.schema,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "target": self.target,
            "pipeline": self.pipeline,
            "scanners": self.scanners,
            "counts": count_severities(self.findings),
            "findings": [f.to_dict() for f in fs],
            "gate": self.gate,
            "dynamic": self.dynamic,
        }
