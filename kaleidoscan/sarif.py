"""SARIF 2.1.0 read/validate/write (canonical), fingerprinting, normalization to C2."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from kaleidoscan.redact import redact
from kaleidoscan.severity import map_severity
from kaleidoscan.types import LINE_BUCKET, Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_VOLATILE_KEYS = {"startTimeUtc", "endTimeUtc", "timeUtc", "machine", "account", "processId"}
_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.I)


class SarifError(ValueError):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


def validate(log: Any) -> list[str]:
    """Structural SARIF 2.1.0 check. Returns a list of problems (empty = valid)."""
    p: list[str] = []
    if not isinstance(log, dict):
        return ["log is not an object"]
    if log.get("version") != SARIF_VERSION:
        p.append(f"version must be {SARIF_VERSION!r}, got {log.get('version')!r}")
    runs = log.get("runs")
    if not isinstance(runs, list):
        return p + ["runs must be an array"]
    for i, run in enumerate(runs):
        if not isinstance(run, dict):
            p.append(f"runs[{i}] is not an object")
            continue
        driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
            p.append(f"runs[{i}].tool.driver.name missing")
        results = run.get("results", [])
        if not isinstance(results, list):
            p.append(f"runs[{i}].results must be an array")
            continue
        for j, r in enumerate(results):
            at = f"runs[{i}].results[{j}]"
            if not isinstance(r, dict):
                p.append(f"{at} is not an object")
                continue
            msg = r.get("message")
            if not isinstance(msg, dict) or not isinstance(msg.get("text", msg.get("id")), str):
                p.append(f"{at}.message.text missing")
            if "locations" in r and not isinstance(r["locations"], list):
                p.append(f"{at}.locations must be an array")
    return p


def read_sarif(path: str | os.PathLike) -> dict:
    try:
        log = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise SarifError([f"cannot read {path}: {e}"]) from e
    problems = validate(log)
    if problems:
        raise SarifError(problems)
    return log


def _strip_volatile(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: _strip_volatile(v) for k, v in o.items() if k not in _VOLATILE_KEYS}
    if isinstance(o, list):
        return [_strip_volatile(v) for v in o]
    return o


def redact_sarif(o: Any) -> Any:
    if isinstance(o, str):
        return redact(o)[0]
    if isinstance(o, dict):
        return {k: redact_sarif(v) for k, v in o.items()}
    if isinstance(o, list):
        return [redact_sarif(v) for v in o]
    return o


def _dumps(o: Any) -> str:
    return json.dumps(o, sort_keys=True, indent=2, ensure_ascii=False, separators=(",", ": ")) + "\n"


def _loc_key(r: dict) -> tuple:
    locs = r.get("locations") or [{}]
    pl = (locs[0] or {}).get("physicalLocation", {}) or {}
    reg = pl.get("region", {}) or {}
    return (
        (pl.get("artifactLocation", {}) or {}).get("uri", ""),
        reg.get("startLine", 0), reg.get("startColumn", 0),
    )


def canonicalize(log: dict, *, redact_secrets: bool = True) -> dict:
    """Deterministic form: volatile fields removed, runs/rules/results sorted, secrets redacted."""
    log = _strip_volatile(log)
    if redact_secrets:
        log = redact_sarif(log)
    runs = []
    for run in log.get("runs", []):
        run = dict(run)
        driver = run.get("tool", {}).get("driver", {})
        if isinstance(driver.get("rules"), list):
            driver["rules"] = sorted(driver["rules"], key=lambda r: r.get("id", ""))
        if isinstance(run.get("results"), list):
            run["results"] = sorted(
                run["results"],
                key=lambda r: (r.get("ruleId", ""), *_loc_key(r), (r.get("message") or {}).get("text", "")),
            )
        runs.append(run)
    runs.sort(key=lambda r: (r.get("tool", {}).get("driver", {}).get("name", ""),
                             r.get("tool", {}).get("driver", {}).get("version", "")))
    out = {"$schema": log.get("$schema", SARIF_SCHEMA), "version": SARIF_VERSION, "runs": runs}
    return out


def dumps_canonical(log: dict, *, redact_secrets: bool = True) -> str:
    return _dumps(canonicalize(log, redact_secrets=redact_secrets))


def write_sarif(path: str | os.PathLike, log: dict, *, redact_secrets: bool = True) -> None:
    """Atomic, byte-deterministic write."""
    problems = validate(log)
    if problems:
        raise SarifError(problems)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = dumps_canonical(log, redact_secrets=redact_secrets)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".sarif-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# ---------- fingerprint / normalization ----------

def normalize_path(uri: str, root: str | os.PathLike | None = None) -> str:
    """Relative, POSIX-style path independent of checkout prefix / OS."""
    s = uri.strip().replace("\\", "/")
    if s.startswith("file://"):
        s = s[len("file://"):]
        if re.match(r"^/[A-Za-z]:/", s):
            s = s[1:]
    if root is not None:
        r = str(root).replace("\\", "/").rstrip("/")
        if r and (s == r or s.startswith(r + "/")):
            s = s[len(r):]
    s = re.sub(r"^[A-Za-z]:/", "", s)  # drive letter
    parts = [x for x in PurePosixPath(s).parts if x not in ("/", ".")]
    return "/".join(parts)


def normalize_cwe(values: list[str]) -> list[str]:
    out = {f"CWE-{int(m.group(1))}" for v in values if (m := _CWE_RE.search(v))}
    return sorted(out, key=lambda c: int(c[4:]))


def normalize_rule_id(rule_id: str) -> str:
    return rule_id.strip().lower()


def normalize_snippet(s: str) -> str:
    return " ".join(s.split())


def line_bucket(line: int) -> int:
    return max(line, 0) // LINE_BUCKET


def fingerprint(rule_id: str, cwe: list[str], relpath: str, start_line: int, snippet: str) -> str:
    parts = [normalize_rule_id(rule_id), ",".join(normalize_cwe(cwe)), relpath,
             str(line_bucket(start_line)), normalize_snippet(snippet)]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def _cwes(result: dict, rule: dict) -> list[str]:
    vals: list[str] = []
    for src in (result.get("properties") or {}, rule.get("properties") or {}):
        c = src.get("cwe")
        vals += [c] if isinstance(c, str) else [x for x in (c or []) if isinstance(x, str)]
        vals += [t for t in src.get("tags", []) or [] if isinstance(t, str) and _CWE_RE.search(t)]
    for rel in rule.get("relationships", []) or []:
        tgt = rel.get("target", {}) if isinstance(rel, dict) else {}
        if "cwe" in str(tgt.get("toolComponent", {}).get("name", "")).lower() and tgt.get("id"):
            vals.append(f"CWE-{tgt['id']}")
    return normalize_cwe(vals)


def _flow(result: dict, root) -> list[dict] | None:
    steps = []
    for cf in result.get("codeFlows", []) or []:
        for tf in cf.get("threadFlows", []) or []:
            for loc in tf.get("locations", []) or []:
                l = loc.get("location", {})
                pl = l.get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                note, _ = redact(l.get("message", {}).get("text", ""))
                steps.append({"path": normalize_path(uri, root),
                              "line": pl.get("region", {}).get("startLine", 0), "note": note})
        if steps:
            return steps
    return None


def findings_from_sarif(log: dict, scanner_id: str | None = None, root=None,
                        *, is_secret_scanner: bool = False) -> list[Finding]:
    """Normalize SARIF results to C2 findings (redacted, deterministic order)."""
    problems = validate(log)
    if problems:
        raise SarifError(problems)
    out: list[Finding] = []
    for run in log["runs"]:
        driver = run["tool"]["driver"]
        sid = scanner_id or driver["name"].lower()
        rules = {r.get("id"): r for r in driver.get("rules", []) or [] if isinstance(r, dict)}
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            rule = rules.get(rule_id, {})
            locs = res.get("locations") or [{}]
            pl = (locs[0] or {}).get("physicalLocation", {}) or {}
            reg = pl.get("region", {}) or {}
            path = normalize_path((pl.get("artifactLocation", {}) or {}).get("uri", ""), root)
            start = int(reg.get("startLine", 0) or 0)
            end = int(reg.get("endLine", start) or start)
            snippet_raw = (reg.get("snippet", {}) or {}).get("text", "")
            snippet, s_changed = redact(snippet_raw)
            msg, m_changed = redact((res.get("message") or {}).get("text", ""))
            flow = _flow(res, root)
            f_changed = any(redact(s["note"])[1] for s in flow or [])
            cwe = _cwes(res, rule)
            props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}
            level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
            sev, conf = map_severity(sid, level, props.get("security-severity"), props.get("native-severity"))
            out.append(Finding(
                fingerprint=fingerprint(rule_id, cwe, path, start, snippet),
                scanner_ids=[sid], rule_ids={sid: rule_id}, cwe=cwe,
                severity=sev, confidence=conf, message=msg,
                location={"path": path, "start_line": start, "end_line": end},
                code_flow=flow,
                secret_redacted=bool(is_secret_scanner or s_changed or m_changed or f_changed),
            ))
    out.sort(key=lambda f: (f.location["path"], f.location["start_line"], f.fingerprint))
    return out
