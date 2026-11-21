"""Shared adapter helpers (C1). Adapters are plain classes satisfying `types.Adapter`."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Iterable

from kaleidoscan.types import (  # re-exported for adapter authors
    Adapter, ScannerInfo, ScannerKind, ScannerResult, ScannerStatus, Target,
)

__all__ = ["Adapter", "ScannerInfo", "ScannerKind", "ScannerResult", "ScannerStatus", "Target",
           "SKIP_DIRS", "cfg_get", "count_files", "result", "Stopwatch"]

SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
                       "target", "dist", "build", ".tox", ".mypy_cache"})


def cfg_get(cfg: Any, key: str, default: Any = None) -> Any:
    """Read a per-scanner option from a ScannerSpec-like object or plain dict."""
    if cfg is None:
        return default
    src = cfg if isinstance(cfg, dict) else getattr(cfg, "config", None)
    if isinstance(src, dict):
        return src.get(key, default)
    return default


def count_files(root: Path, exts: Iterable[str]) -> int:
    """Count files with the given extensions under root (or 1/0 if root is a file).

    Does not follow symlinked directories; skips vendor/build dirs. Used where a scanner
    does not report how many files it analyzed, so EMPTY can be told apart from clean.
    """
    exts = tuple(e.lower() for e in exts)
    if root.is_file():
        return int(root.name.lower().endswith(exts))
    n = 0
    for _dp, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        n += sum(1 for f in files if f.lower().endswith(exts))
    return n


class Stopwatch:
    def __init__(self) -> None:
        self._t0 = time.monotonic()

    @property
    def ms(self) -> int:
        return int((time.monotonic() - self._t0) * 1000)


def result(scanner_id: str, status: ScannerStatus, *, version: str | None = None,
           files: int | None = None, sarif: dict | None = None, ms: int = 0,
           detail: str = "") -> ScannerResult:
    return ScannerResult(scanner_id=scanner_id, status=status, version=version,
                         files_analyzed=files, sarif=sarif, duration_ms=ms, detail=detail[:500])
