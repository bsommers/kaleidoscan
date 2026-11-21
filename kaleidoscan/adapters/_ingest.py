"""Shared helpers for ingestion adapters (result files -> SARIF). Inputs are untrusted data:
never executed, never imported; paths validated; sizes, counts and string lengths capped."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from kaleidoscan.redact import redact

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
HARD_MAX_BYTES = 64 * 1024 * 1024
MAX_INPUTS = 64
MAX_RECORDS = 10_000
MAX_MESSAGE = 500
MAX_URI = 1024
MAX_RULE = 100
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_CWE_RE = re.compile(r"CWE[-_]?(\d{1,4})", re.IGNORECASE)


class IngestError(Exception):
    """An input could not be accepted; str() is safe to show (no file contents)."""


def clean_text(v: Any, limit: int, *, secrets: bool = True) -> str:
    s = _CTRL.sub(" ", str(v))
    if secrets:
        s, _ = redact(s)
    return s[:limit]


def clean_uri(v: Any) -> str:
    return clean_text(v, MAX_URI, secrets=False).replace("\\", "/").strip() or "unknown"


def normalize_cwe(raw: Any, default: str = "CWE-UNKNOWN") -> str:
    s = str(raw)
    m = _CWE_RE.search(s)
    if m:
        n = int(m.group(1))
        return f"CWE-{n:03d}" if n < 1000 else f"CWE-{n}"
    return clean_text(s.strip(), MAX_RULE, secrets=False) or default


def parse_line(raw: Any, default: int = 1) -> int:
    """Line number or address offset (base auto-detect); clamped to >= 1."""
    try:
        n = int(str(raw), 0) if not isinstance(raw, bool) else default
    except (ValueError, TypeError):
        return default
    return min(max(1, n), 2**31 - 1)


def configured_inputs(cfg_inputs: Any) -> list[Any]:
    if cfg_inputs is None:
        return []
    if isinstance(cfg_inputs, (str, os.PathLike, dict)):
        cfg_inputs = [cfg_inputs]
    if not isinstance(cfg_inputs, (list, tuple)):
        raise IngestError("`inputs` must be a list of file paths")
    if len(cfg_inputs) > MAX_INPUTS:
        raise IngestError(f"too many inputs (max {MAX_INPUTS})")
    return list(cfg_inputs)


def allowed_roots(cfg_dirs: Any, target_path: Path | None) -> list[Path]:
    dirs: list[Any] = []
    if isinstance(cfg_dirs, (str, os.PathLike)):
        dirs = [cfg_dirs]
    elif isinstance(cfg_dirs, (list, tuple)):
        dirs = list(cfg_dirs)
    elif target_path is not None:
        dirs = [target_path if target_path.is_dir() else target_path.parent]
    roots = []
    for d in dirs:
        try:
            roots.append(Path(d).expanduser().resolve(strict=True))
        except (OSError, RuntimeError, ValueError):
            continue
    return roots


def validate_input(raw: Any, roots: list[Path], max_bytes: int) -> Path:
    """Return the resolved path of a regular file under an allowed dir, else IngestError."""
    if not isinstance(raw, (str, os.PathLike)) or "\x00" in str(raw) or not str(raw):
        raise IngestError("input path is not a valid string")
    p = Path(raw).expanduser()
    name = p.name
    try:
        if p.is_symlink():
            raise IngestError(f"{name}: symlinked input rejected")
        rp = p.resolve(strict=True)
    except IngestError:
        raise
    except (OSError, RuntimeError):
        raise IngestError(f"{name}: not found or unreadable") from None
    if not any(rp == r or r in rp.parents for r in roots):
        raise IngestError(f"{name}: outside allowed directories")
    try:
        st = rp.stat()
    except OSError:
        raise IngestError(f"{name}: not readable") from None
    if not rp.is_file():
        raise IngestError(f"{name}: not a regular file")
    if st.st_size > max_bytes:
        raise IngestError(f"{name}: exceeds size cap of {max_bytes} bytes")
    return rp


def read_capped(path: Path, max_bytes: int) -> str:
    """Read at most max_bytes (+1 to detect growth); no symlink following on open."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as f:
            data = f.read(max_bytes + 1)
    except OSError:
        raise IngestError(f"{path.name}: not readable") from None
    if len(data) > max_bytes:
        raise IngestError(f"{path.name}: exceeds size cap of {max_bytes} bytes")
    return data.decode("utf-8", "replace")


def max_bytes_from(v: Any) -> int:
    try:
        n = int(v) if v is not None else DEFAULT_MAX_BYTES
    except (TypeError, ValueError):
        return DEFAULT_MAX_BYTES
    return min(max(1, n), HARD_MAX_BYTES)


def loads_json(text: str) -> Any:
    """Defensive JSON parse; returns None on failure (incl. RecursionError on deep nesting)."""
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def sarif_doc(driver: str, version: str, results: list[dict], properties: dict | None = None) -> dict:
    run: dict[str, Any] = {"tool": {"driver": {"name": driver, "version": version}}, "results": results}
    if properties:
        run["properties"] = properties
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def sarif_result(rule_id: str, message: str, uri: str, line: int) -> dict:
    return {"ruleId": rule_id, "message": {"text": message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                "region": {"startLine": line}}}]}
