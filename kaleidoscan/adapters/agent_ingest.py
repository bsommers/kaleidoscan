"""LLM-agent review ingestion adapter: converts saved agent output (JSON findings, markdown
tables, bullet text) to SARIF. Nothing is executed; ported from Synth's
tools/adapt_agent_output.py.

Agent findings are an AI-review *view*, not scanner ground truth: the SARIF run carries
`properties: {"kaleidoscan.view": "ai-review"}` so scoring can treat them separately.
Optional telemetry (tokens, duration, cost) found in the output goes in `properties.telemetry`.

Config options: `inputs`, `allowed_dirs`, `max_bytes` (see binary_ingest).
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

ID = "llm-agent-review"
VIEW = {"kaleidoscan.view": "ai-review"}
CWE_RE = re.compile(r"\b(CWE-\d{1,4})\b", re.IGNORECASE)
FILE_LINE_RE = re.compile(r"([a-zA-Z0-9_\-./\\]{1,300}\.[a-zA-Z0-9]{1,10})[:#\s]{1,4}(?:line\s{1,4})?(\d{1,9})",
                          re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?:json)?[ \t]*\n(.*?)```", re.DOTALL)
_LIST_KEYS = ("findings", "results", "vulnerabilities", "alerts")


def _finding(uri: Any, line: Any, rule: Any, msg: Any) -> dict | None:
    msg_s = str(msg)
    cwe = CWE_RE.search(str(rule)) or CWE_RE.search(msg_s)
    rule_id = cwe.group(1).upper() if cwe else ing.clean_text(rule, ing.MAX_RULE, secrets=False).strip()
    if not uri or not rule_id:
        return None
    try:
        n = int(line)
    except (ValueError, TypeError):
        n = 0
    return {"uri": ing.clean_uri(uri), "line": max(1, min(n, 2**31 - 1)), "rule_id": rule_id,
            "message": ing.clean_text(msg_s, ing.MAX_MESSAGE)}


def parse_json_findings(text: str) -> list[dict] | None:
    data = ing.loads_json(text.strip())
    if data is None:
        m = _FENCE_RE.search(text)
        data = ing.loads_json(m.group(1)) if m else None
    if isinstance(data, dict):
        for k in _LIST_KEYS:
            if isinstance(data.get(k), list):
                data = data[k]
                break
        else:
            data = [data]
    if not isinstance(data, list):
        return None
    out = []
    for it in data[: ing.MAX_RECORDS]:
        if not isinstance(it, dict):
            continue
        f = _finding(
            it.get("file") or it.get("filename") or it.get("path") or it.get("uri") or "",
            it.get("line") or it.get("start_line") or it.get("line_number") or it.get("startLine") or 0,
            it.get("cwe") or it.get("rule_id") or it.get("ruleId") or it.get("cwe_id") or it.get("type") or "",
            it.get("message") or it.get("description") or it.get("title") or "LLM finding")
        if f:
            out.append(f)
    return out or None


def parse_markdown_table_findings(text: str) -> list[dict]:
    out: list[dict] = []
    headers: list[str] = []
    for line in text.splitlines()[: ing.MAX_RECORDS * 4]:
        s = line.strip()[:4000]
        if not (s.startswith("|") and s.endswith("|")):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not headers:
            headers = [c.lower() for c in cells]
            continue
        if all(set(c) <= {"-", " ", ":"} for c in cells):
            continue
        uri, line_n, rule, msg = "", 0, "", "LLM finding"
        for k, v in zip(headers, cells):
            if any(t in k for t in ("file", "path", "location", "uri")):
                m = FILE_LINE_RE.search(v)
                uri, line_n = (m.group(1), int(m.group(2))) if m else (v, line_n)
            elif any(t in k for t in ("line", "start")):
                digits = re.sub(r"\D", "", v)[:9]
                line_n = int(digits) if digits else line_n
            elif any(t in k for t in ("cwe", "rule", "vuln", "type", "weakness")):
                m = CWE_RE.search(v)
                rule = m.group(1).upper() if m else v
            elif any(t in k for t in ("desc", "msg", "message", "detail", "title")):
                msg = v
        if uri and not rule:
            m = CWE_RE.search(s)
            rule = m.group(1).upper() if m else ""
        f = _finding(uri, line_n, rule, msg) if uri else None
        if f:
            out.append(f)
    return out


def parse_text_findings(text: str) -> list[dict]:
    out = []
    for line in text.splitlines()[: ing.MAX_RECORDS * 4]:
        line = line[:1000]
        c, fl = CWE_RE.search(line), FILE_LINE_RE.search(line)
        if c and fl:
            out.append(_finding(fl.group(1), fl.group(2), c.group(1).upper(), line.strip("-*# \t")))
    return [f for f in out if f]


_TEL = {
    "prompt_tokens": ("prompt_tokens", "input_tokens", "prompt_eval_count", "promptTokens", "inputTokens"),
    "completion_tokens": ("completion_tokens", "output_tokens", "eval_count", "completionTokens", "outputTokens"),
    "total_tokens": ("total_tokens", "totalTokens"),
    "duration_seconds": ("duration_seconds", "latency_seconds", "elapsed_seconds", "time_seconds"),
    "cost_usd": ("cost_usd", "total_cost", "estimated_cost_usd", "totalCost"),
}


def parse_telemetry(text: str) -> dict[str, Any]:
    tel: dict[str, Any] = dict.fromkeys(_TEL)
    data = ing.loads_json(text.strip())
    if isinstance(data, dict):
        boxes = [data] + [data[k] for k in ("usage", "telemetry", "stats", "metadata", "metrics", "token_usage")
                          if isinstance(data.get(k), dict)]
        for field, keys in _TEL.items():
            for b in boxes:
                v = next((b[k] for k in keys if isinstance(b.get(k), (int, float)) and not isinstance(b[k], bool)),
                         None)
                if v is not None:
                    tel[field] = float(v) if field in ("duration_seconds", "cost_usd") else int(v)
                    break
    head = text[:200_000]
    for field, rx, cast in (
        ("prompt_tokens", r"(?:prompt|input)\s{1,4}tokens?[:=\s]{1,4}([0-9,]{1,15})", "i"),
        ("completion_tokens", r"(?:completion|output)\s{1,4}tokens?[:=\s]{1,4}([0-9,]{1,15})", "i"),
        ("total_tokens", r"total\s{1,4}tokens?[:=\s]{1,4}([0-9,]{1,15})", "i"),
        ("cost_usd", r"(?:total|estimated)\s{1,4}cost[:=\s]{1,4}\$?([0-9]{1,12}(?:\.[0-9]{1,12})?)", "f"),
    ):
        m = re.search(rx, head, re.IGNORECASE) if tel[field] is None else None
        if m:
            try:
                tel[field] = float(m.group(1)) if cast == "f" else int(m.group(1).replace(",", ""))
            except ValueError:
                pass
    if tel["total_tokens"] is None and None not in (tel["prompt_tokens"], tel["completion_tokens"]):
        tel["total_tokens"] = tel["prompt_tokens"] + tel["completion_tokens"]
    return tel


def convert(text: str) -> tuple[list[dict], dict[str, Any]]:
    """Return (SARIF results, telemetry) for one agent-output file's text."""
    findings = parse_json_findings(text) or parse_markdown_table_findings(text) or parse_text_findings(text)
    results = [ing.sarif_result(f["rule_id"], f["message"], f["uri"], f["line"]) for f in findings[: ing.MAX_RECORDS]]
    return results, parse_telemetry(text)


class AgentIngestAdapter:
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
                       "no inputs configured: set `inputs` to saved LLM-agent review output files")
        roots = ing.allowed_roots(cfg_get(cfg, "allowed_dirs"), Path(t.path))
        cap = ing.max_bytes_from(cfg_get(cfg, "max_bytes"))
        results: list[dict] = []
        telemetry: list[dict] = []
        parsed, problems = 0, []
        for raw in inputs:
            try:
                text = ing.read_capped(ing.validate_input(raw, roots, cap), cap)
            except ing.IngestError as e:
                problems.append(str(e))
                continue
            parsed += 1
            r, tel = convert(text)
            results.extend(r)
            results = results[: ing.MAX_RECORDS]
            if any(v is not None for v in tel.values()):
                telemetry.append(tel)
        note = "; ".join(problems[:3])
        if parsed == 0:
            return out(ScannerStatus.ERROR, f"no usable input: {note}")
        if not results:
            return out(ScannerStatus.EMPTY, "inputs contained no findings" + (f"; {note}" if note else ""), parsed)
        props: dict[str, Any] = dict(VIEW)
        if telemetry:
            props["telemetry"] = telemetry[0] if len(telemetry) == 1 else telemetry
        doc = ing.sarif_doc("llm-agent-review", "ingest", results, props)
        bad = sarif_mod.validate(doc)
        if bad:
            return out(ScannerStatus.ERROR, "invalid SARIF: " + "; ".join(bad[:3]), parsed)
        return out(ScannerStatus.OK, note, parsed, doc)
