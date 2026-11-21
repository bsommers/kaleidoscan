"""Shared binary resolution for scanner adapters that ship as plain executables.

Order (C17, local channels): `bin` in the scanner config, $<ID>_BIN, `<id>` on PATH, then a
few well-known local venv/tool directories (colon-separated $KALEIDOSCAN_TOOL_DIRS, then
$<ID>_VENV/bin, then ~/src/synth/.scanners/venv/bin).
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil

from kaleidoscan.adapters.base import cfg_get


def _is_exe(p: Path) -> bool:
    return p.is_file() and os.access(p, os.X_OK)


def resolve_exe(name: str, cfg=None, env=None) -> tuple[list[str] | None, str]:
    """Return (argv_prefix, channel); argv_prefix is None when nothing usable is found."""
    env = os.environ if env is None else env
    up = name.upper().replace("-", "_")
    explicit = cfg_get(cfg, "bin") or env.get(f"{up}_BIN")
    if explicit:
        p = Path(explicit).expanduser()
        return ([str(p)], "explicit") if _is_exe(p) else (None, "explicit")
    found = shutil.which(name, path=env.get("PATH"))
    if found:
        return [found], "path"
    dirs = [d for d in (env.get("KALEIDOSCAN_TOOL_DIRS") or "").split(":") if d]
    if env.get(f"{up}_VENV"):
        dirs.append(str(Path(env[f"{up}_VENV"]) / "bin"))
    dirs.append("~/src/synth/.scanners/venv/bin")
    for d in dirs:
        p = Path(d).expanduser() / name
        if _is_exe(p):
            return [str(p)], "local"
    return None, "path"


def rel_uri(uri: str, root: Path) -> str:
    """Make an absolute/file:// artifact URI relative to the scan root (POSIX), else unchanged."""
    u = uri[7:] if uri.startswith("file://") else uri
    try:
        return Path(u).resolve().relative_to(root).as_posix() if os.path.isabs(u) else u
    except ValueError:
        return uri
