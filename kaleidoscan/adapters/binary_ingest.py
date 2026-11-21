"""Binary-analysis ingestion adapter: converts existing Ghidra / angr / Binary Ninja result
files to SARIF. Nothing is executed and no tool is invoked; ported from Synth's
tools/adapt_binary_sast.py.

Config options (scanner `config`):
  inputs       list of result-file paths, or {"path": ..., "tool": ghidra|angr|binja|auto}
  tool         default tool for string inputs (ghidra|angr|binja|auto; default auto)
  allowed_dirs directories inputs must live under (default: the scan target)
  max_bytes    per-file size cap (default 10 MiB, hard max 64 MiB)

Binary Ninja is commercial and bring-your-own: this adapter only reads an export that you
produced with your own licensed install (a tags/bookmarks JSON); it ships and runs nothing.
Ghidra and angr outputs are likewise produced by you and ingested here.
Findings are static-analysis results (kind sast), not an AI-review view.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from kaleidoscan import sarif as sarif_mod
from kaleidoscan.adapters import _ingest as ing
from kaleidoscan.adapters.base import (
    ScannerInfo, ScannerKind, ScannerResult, ScannerStatus, Stopwatch, Target, cfg_get, result,
)

ID = "binary-analysis"
TOOLS = ("ghidra", "angr", "binja")
_TEXT_RE = re.compile(r"(\S{1,300}\.(?:s|asm|wat)):(\d{1,9}):[ \t]{0,8}(?:\[(CWE-\d{1,4})\])?[ \t]{0,8}(.{0,500})")


def _items(data: Any, keys: tuple[str, ...]) -> list[dict]:
    if isinstance(data, dict):
        items: Any = []
        for k in keys:
            if isinstance(data.get(k), list):
                items = data[k]
                break
    else:
        items = data
    return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []


def _first(item: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if item.get(k) is not None:
            return item[k]
    return default


def _res(rule: Any, msg: Any, uri: Any, line: Any, rule_default: str) -> dict:
    rid = ing.normalize_cwe(rule if rule is not None else rule_default)
    return ing.sarif_result(rid, ing.clean_text(msg, ing.MAX_MESSAGE), ing.clean_uri(uri), ing.parse_line(line))


def adapt_ghidra(data: Any) -> list[dict]:
    out = []
    for it in _items(data, ("findings", "alerts")):
        rule = _first(it, "cwe", "rule_id", "vuln_type", default="CWE-121")
        out.append(_res(rule, _first(it, "message", "description", default=f"Ghidra alert for {rule}"),
                        _first(it, "file", "source_file", "function_name", default="binary.s"),
                        _first(it, "line", "line_number", "address_offset", default=1), "CWE-121"))
    return out


def adapt_angr(data: Any) -> list[dict]:
    out = []
    for it in _items(data, ("vulnerabilities", "states")):
        rule = _first(it, "bug_type", "cwe_id", default="CWE-119")
        out.append(_res(rule, _first(it, "details", "error",
                                     default=f"angr unconstrained symbolic state leading to {rule}"),
                        _first(it, "source", "binary", default="target.s"),
                        _first(it, "source_line", "line", "address_offset", default=1), "CWE-119"))
    return out


def adapt_binja(data: Any) -> list[dict]:
    out = []
    for it in _items(data, ("tags", "bookmarks")):
        rule = _first(it, "name", "tag", default="CWE-787")
        out.append(_res(rule, _first(it, "comment", "data", default=f"Binary Ninja high-level IL alert {rule}"),
                        _first(it, "file_path", "module", default="decompiled.s"),
                        _first(it, "hlil_line", "line", "address_offset", default=1), "CWE-787"))
    return out


_ADAPTERS = {"ghidra": adapt_ghidra, "angr": adapt_angr, "binja": adapt_binja}


def detect_tool(data: Any) -> str:
    """Guess the producing tool from the JSON shape; ghidra-style is the generic default."""
    if isinstance(data, dict):
        if "vulnerabilities" in data or "states" in data:
            return "angr"
        if "tags" in data or "bookmarks" in data:
            return "binja"
        return "ghidra"
    for it in data if isinstance(data, list) else []:
        if isinstance(it, dict):
            if {"bug_type", "source_line", "cwe_id", "details"} & it.keys():
                return "angr"
            if {"hlil_line", "tag", "comment", "module", "file_path"} & it.keys():
                return "binja"
            break
    return "ghidra"


def parse_text(text: str) -> list[dict]:
    """Line-oriented CLI report fallback: `file.s:12: [CWE-121] message`."""
    out = []
    for line in text.splitlines()[: ing.MAX_RECORDS]:
        m = _TEXT_RE.search(line[:1200])
        if m:
            out.append({"file": m.group(1), "line": int(m.group(2)),
                        "cwe": m.group(3) or "CWE-121", "message": m.group(4) or "Binary analysis finding"})
    return out


def convert(text: str, tool: str = "auto") -> list[dict]:
    """Return SARIF results for one input file's text."""
    data = ing.loads_json(text)
    if data is None:
        return adapt_ghidra(parse_text(text))
    if tool not in _ADAPTERS:
        tool = detect_tool(data)
    return _ADAPTERS[tool](data)[: ing.MAX_RECORDS]


class BinaryIngestAdapter:
    info = ScannerInfo(id=ID, kind=ScannerKind.SAST, languages=frozenset({"*"}),
                       license="MIT", restricted=False, offline_capable=True)

    def __init__(self, cfg=None):
        self._cfg = cfg

    def detect(self) -> tuple[bool, str | None]:
        return True, "ingest"

    def applicable(self, t: Target) -> bool:
        return True

    def run(self, t: Target, cfg, *, timeout_s: int) -> ScannerResult:
        sw = Stopwatch()
        out = lambda st, d, f=None, s=None: result(ID, st, version="ingest", files=f, sarif=s,  # noqa: E731
                                                   ms=sw.ms, detail=d)
        cfg = cfg if cfg is not None else self._cfg
        try:
            inputs = ing.configured_inputs(cfg_get(cfg, "inputs"))
        except ing.IngestError as e:
            return out(ScannerStatus.ERROR, str(e))
        if not inputs:
            return out(ScannerStatus.SKIPPED,
                       "no inputs configured: set `inputs` to Ghidra/angr/Binary Ninja result files "
                       "(Binary Ninja is bring-your-own; export its tags/bookmarks as JSON)")
        roots = ing.allowed_roots(cfg_get(cfg, "allowed_dirs"), Path(t.path))
        cap = ing.max_bytes_from(cfg_get(cfg, "max_bytes"))
        default_tool = str(cfg_get(cfg, "tool", "auto")).lower()
        results: list[dict] = []
        parsed, problems = 0, []
        for ent in inputs:
            raw, tool = (ent.get("path"), str(ent.get("tool", default_tool)).lower()) \
                if isinstance(ent, dict) else (ent, default_tool)
            try:
                text = ing.read_capped(ing.validate_input(raw, roots, cap), cap)
            except ing.IngestError as e:
                problems.append(str(e))
                continue
            parsed += 1
            results.extend(convert(text, tool))
            results = results[: ing.MAX_RECORDS]
        note = "; ".join(problems[:3])
        if parsed == 0:
            return out(ScannerStatus.ERROR, f"no usable input: {note}")
        if not results:
            return out(ScannerStatus.EMPTY, "inputs contained no findings" + (f"; {note}" if note else ""), parsed)
        doc = ing.sarif_doc("binary-analysis", "ingest", results)
        bad = sarif_mod.validate(doc)
        if bad:
            return out(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(bad[:3]), parsed)
        return out(ScannerStatus.OK, note, parsed, doc)
