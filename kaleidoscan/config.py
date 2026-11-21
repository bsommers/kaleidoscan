"""Pipeline definition (contract C4): `kaleidoscan.yaml` models, loader and profiles.

Unknown keys are rejected, relative paths resolve against the config file's directory, and the
reserved `dynamic:` key is an error until dynamic testing exists (contract C9).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from kaleidoscan.catalog import SCANNERS

Severity = Literal["critical", "high", "medium", "low", "info"]
ReportFormat = Literal["sarif", "html", "markdown", "junit", "json"]
DYNAMIC_ERROR = "dynamic testing not implemented (the `dynamic:` key is reserved, see docs/DYNAMIC_TESTING.md)"
KNOWN_SCANNER_IDS = frozenset(s[0] for s in SCANNERS)


class ConfigError(ValueError):
    """Invalid pipeline configuration (CLI exit code 2)."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Target(_Strict):
    path: Path
    exclude: list[str] = Field(default_factory=list)


class ScannerSpec(_Strict):
    id: str
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class FailOn(_Strict):
    severity_at_least: Severity = "high"
    new_only: bool = False
    baseline: Path | None = None


class Policy(_Strict):
    fail_on: FailOn = Field(default_factory=FailOn)
    require_scanners: list[str] = Field(default_factory=list)
    suppressions: Path | None = None


class Limits(_Strict):
    timeout_s: int = Field(600, ge=1, le=86400)
    max_output_mb: int = Field(64, ge=1, le=4096)
    max_parallel: int = Field(4, ge=1, le=64)


class Pipeline(_Strict):
    version: Literal[1]
    name: str = "default"
    target: Target
    scanners: list[ScannerSpec]
    dynamic: Any = None
    policy: Policy = Field(default_factory=Policy)
    reports: list[ReportFormat] = Field(default_factory=lambda: ["sarif", "html", "markdown", "junit", "json"])
    limits: Limits = Field(default_factory=Limits)

    @field_validator("dynamic")
    @classmethod
    def _dynamic_reserved(cls, v: Any) -> Any:
        if v is not None:
            raise ValueError(DYNAMIC_ERROR)
        return v

    @model_validator(mode="after")
    def _cross_checks(self) -> "Pipeline":
        seen: set[str] = set()
        for s in self.scanners:
            if s.id not in KNOWN_SCANNER_IDS:
                raise ValueError(f"unknown scanner id {s.id!r}")
            if s.id in seen:
                raise ValueError(f"duplicate scanner id {s.id!r}")
            seen.add(s.id)
        enabled = {s.id for s in self.scanners if s.enabled}
        missing = [r for r in self.policy.require_scanners if r not in enabled]
        if missing:
            raise ValueError(f"policy.require_scanners {missing} are not enabled scanners in this pipeline")
        return self

    def hash(self) -> str:
        blob = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:12]

    def pipeline_id(self) -> str:
        """`name@hash`, the value recorded in the run envelope (C3)."""
        return f"{self.name}@{self.hash()}"


# Profiles (scanners.md section 6). Each maps a validated-raw dict to an overridden dict.
_FAST = frozenset({"flowscope", "bandit", "gosec", "semgrep", "opengrep", "gitleaks"})


def _fast(d: dict) -> None:
    for s in d["scanners"]:
        s["enabled"] = bool(s.get("enabled", True)) and s["id"] in _FAST
    lim = d.setdefault("limits", {})
    lim["timeout_s"] = min(int(lim.get("timeout_s", 600)), 120)


def _full(d: dict) -> None:
    for s in d["scanners"]:
        s["enabled"] = True


def _ci(d: dict) -> None:
    d.setdefault("policy", {}).setdefault("fail_on", {})["new_only"] = True
    d["reports"] = ["sarif", "junit", "json"]


PROFILES = {"fast": _fast, "full": _full, "ci": _ci}


def _resolve(d: dict, base: Path) -> None:
    def rp(v: Any) -> Any:
        p = Path(str(v))
        return os.path.normpath(p if p.is_absolute() else base / p)

    if isinstance(d.get("target"), dict) and d["target"].get("path") is not None:
        d["target"]["path"] = rp(d["target"]["path"])
    pol = d.get("policy")
    if isinstance(pol, dict):
        if isinstance(pol.get("fail_on"), dict) and pol["fail_on"].get("baseline"):
            pol["fail_on"]["baseline"] = rp(pol["fail_on"]["baseline"])
        if pol.get("suppressions"):
            pol["suppressions"] = rp(pol["suppressions"])
    for s in d.get("scanners") or []:
        if isinstance(s, dict) and isinstance(s.get("config"), dict) and "offline_rules" in s["config"]:
            s["config"]["offline_rules"] = rp(s["config"]["offline_rules"])


def _fmt(e: ValidationError) -> str:
    out = []
    for err in e.errors():
        loc = ".".join(str(x) for x in err["loc"])
        msg = err["msg"].removeprefix("Value error, ")
        out.append(f"{loc}: {msg}" if loc else msg)
    return "invalid config: " + "; ".join(out)


def parse_config(data: Any, *, base_dir: Path, profile: str | None = None) -> Pipeline:
    """Validate a raw mapping; relative paths resolve against `base_dir`."""
    if not isinstance(data, dict):
        raise ConfigError("invalid config: top level must be a mapping")
    if profile is not None and profile not in PROFILES:
        raise ConfigError(f"unknown profile {profile!r}; choose from {', '.join(sorted(PROFILES))}")
    if data.get("dynamic") is not None:
        raise ConfigError(f"invalid config: dynamic: {DYNAMIC_ERROR}")
    d = json.loads(json.dumps(data, default=str))  # deep copy; never mutate caller data
    _resolve(d, Path(base_dir).resolve())
    scanners = d.get("scanners")
    if profile and isinstance(scanners, list) and all(isinstance(x, dict) and "id" in x for x in scanners):
        PROFILES[profile](d)
    try:
        return Pipeline.model_validate(d)
    except ValidationError as e:
        raise ConfigError(_fmt(e)) from None


def load_config(path: str | Path, *, profile: str | None = None) -> Pipeline:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text())
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise ConfigError(f"invalid YAML in {p}: {e}") from None
    return parse_config(data, base_dir=p.resolve().parent, profile=profile)
