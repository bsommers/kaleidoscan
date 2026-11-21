#!/usr/bin/env python3
"""T-PARITY: kaleidoscan adapters vs Synth's recorded raw scanner output on the same corpus.

For each (scanner, language) pair, compare the set of (native rule id, corpus-relative path,
start line) from the adapter's SARIF against Synth's raw output (`<synth>/.scanners/out`).
Exit 0 only when every compared pair is identical. Pairs whose scanner or Synth output is
missing are reported SKIP with a reason (never silently passed).

  scripts/parity.py [--synth ~/src/synth] [--only semgrep,bandit] [--recorded] [--json]

Default reference = a FRESH run of Synth's exact invocations (scripts/run_scanners.sh) on the
current corpus, written to a scratch dir (Synth's repo is never modified). `--recorded` compares
against Synth's stored `.scanners/out` instead; those files can predate corpus edits, so
differences there are reported but are not evidence of an adapter bug.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from kaleidoscan import adapters
from kaleidoscan.types import ScannerStatus, Target

# (scanner, language, synth raw file, adapter config)
PAIRS = [
    ("flowscope", "python", "flowscope-python.sarif.json", {}),
    ("semgrep", "python", "semgrep-python.raw.json", {"config": "p/security-audit"}),
    ("semgrep", "go", "semgrep-go.raw.json", {"config": "p/security-audit"}),
    ("semgrep", "java", "semgrep-java.raw.json", {"config": "p/security-audit"}),
    ("semgrep", "csharp", "semgrep-csharp.raw.json", {"config": "p/csharp"}),
    ("bandit", "python", "bandit-python.raw.json", {}),
    ("flawfinder", "c", "flawfinder-c.raw.json", {}),
    ("gosec", "go", "gosec-go.raw.json", {}),
]


def rel(uri: str, lang: str) -> str:
    uri = uri.removeprefix("file://")
    marker = f"corpus/{lang}/"
    return uri.split(marker, 1)[1] if marker in uri else uri.lstrip("./")


def keys_from_sarif(log: dict, lang: str, pathmap: dict | None = None, root: str | None = None) -> set:
    out = set()
    for run in log.get("runs", []):
        for r in run.get("results") or []:
            loc = r["locations"][0]["physicalLocation"]
            uri = loc["artifactLocation"]["uri"]
            if root and uri.startswith(root):
                uri = uri[len(root):].lstrip("/")
            if pathmap and uri in pathmap:
                uri = pathmap[uri]
            out.add((r["ruleId"], rel(uri, lang), loc.get("region", {}).get("startLine", 0)))
    return out


def keys_from_bandit_json(d: dict, lang: str) -> set:
    return {(r["test_id"], rel(r["filename"], lang), r["line_number"]) for r in d["results"]}


def synth_keys(scanner: str, lang: str, f: Path, out_dir: Path) -> set:
    d = json.loads(f.read_text())
    if scanner == "bandit":
        return keys_from_bandit_json(d, lang)
    pm = None
    if scanner == "gosec":
        pm = {k: v for k, v in json.loads((out_dir / "gostage-map.json").read_text()).items()}
    return keys_from_sarif(d, lang, pm)


def _tool(synth_root: Path, name: str) -> str | None:
    for d in (synth_root / ".scanners" / "venv" / "bin", synth_root / ".scanners" / "bin"):
        if os.access(d / name, os.X_OK):
            return str(d / name)
    return shutil.which(name)


def _sh(argv, cwd):
    subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=1800)


def fresh_reference(synth_root: Path, scanner: str, lang: str, scratch: Path) -> tuple[Path | None, str]:
    """Re-run Synth's invocation from run_scanners.sh. Returns (raw file, note)."""
    out = scratch / f"{scanner}-{lang}.raw.json"
    rel_corpus = f"corpus/{lang}"
    tool = _tool(synth_root, scanner)
    if scanner == "flowscope":  # same binary as the adapter: isolates harness fidelity from version drift
        from kaleidoscan.adapters.flowscope import resolve_binary
        argv, _ = resolve_binary()
        tool = argv[0] if argv else None
    if not tool:
        return None, "scanner not installed"
    if scanner == "semgrep":
        pack = "p/csharp" if lang == "csharp" else "p/security-audit"
        _sh([tool, "scan", f"--config={pack}", "--sarif", f"--output={out}", "--quiet", rel_corpus], synth_root)
    elif scanner == "bandit":
        _sh([tool, "-r", rel_corpus, "-f", "json", "-o", str(out), "-q"], synth_root)
    elif scanner == "flawfinder":
        with open(out, "wb") as fh:
            subprocess.run([tool, "--sarif", rel_corpus], cwd=synth_root, stdout=fh,
                           stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=1800)
    elif scanner == "gosec":
        stage, mapping = scratch / "gostage", {}
        for cls in sorted((synth_root / "corpus/go").glob("cwe-*")):
            for f in sorted(cls.glob("*.go")):
                dest = stage / cls.name / f.stem / f.name
                dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy(f, dest)
                mapping[str(dest.relative_to(stage))] = str(f)
            for grp in sorted(d for d in cls.glob("*crossfile_*") if d.is_dir()):
                for f in sorted(grp.glob("*.go")):
                    dest = stage / cls.name / grp.name / f.name
                    dest.parent.mkdir(parents=True, exist_ok=True); shutil.copy(f, dest)
                    mapping[str(dest.relative_to(stage))] = str(f)
        (scratch / "gostage-map.json").write_text(json.dumps(mapping))
        _sh([tool, "-fmt=sarif", f"-out={out}", "-no-fail", "./..."], stage)
    elif scanner == "flowscope":
        with tempfile.TemporaryDirectory() as cwd:
            _sh([tool, "scan", str((synth_root / rel_corpus).resolve()), "--output", str(out)], cwd)
    else:
        return None, "no reference recipe"
    return (out, "fresh") if out.is_file() and out.stat().st_size else (None, "reference run produced no output")


def compare(synth_root: Path, only: set[str] | None, recorded: bool = False):
    out_dir = synth_root / ".scanners" / "out"
    scratch = Path(tempfile.mkdtemp(prefix="kscan-parity-", dir=os.environ.get("KSCAN_SCRATCH") or None))
    if not recorded:
        out_dir = scratch
    rows = []
    for scanner, lang, raw, cfg in PAIRS:
        if only and scanner not in only:
            continue
        row = {"scanner": scanner, "language": lang}
        corpus = synth_root / "corpus" / lang
        if recorded:
            f = out_dir / raw
        else:
            f, note = fresh_reference(synth_root, scanner, lang, scratch) if corpus.is_dir() else (None, "corpus missing")
            f = f or scratch / "missing"
        if not f.is_file() or not corpus.is_dir():
            rows.append({**row, "status": "SKIP", "detail": "synth output or corpus missing"})
            continue
        a = adapters.get(scanner)
        ok, ver = a.detect()
        if not ok:
            rows.append({**row, "status": "SKIP", "detail": "scanner not installed"})
            continue
        t = Target(path=corpus.resolve(), kind="dir", languages=frozenset({lang}))
        res = a.run(t, cfg, timeout_s=1800)
        if res.status is not ScannerStatus.OK:
            rows.append({**row, "status": "FAIL", "version": ver,
                         "detail": f"adapter status {res.status}: {res.detail}"})
            continue
        ours = keys_from_sarif(res.sarif, lang, root=str(corpus.resolve()))
        theirs = synth_keys(scanner, lang, f, out_dir)
        rows.append({**row, "status": "PASS" if ours == theirs else "FAIL", "version": ver,
                     "ours": len(ours), "synth": len(theirs),
                     "only_ours": sorted(map(list, ours - theirs))[:10],
                     "only_synth": sorted(map(list, theirs - ours))[:10]})
    shutil.rmtree(scratch, ignore_errors=True)
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--synth", default=os.environ.get("SYNTH_DIR", "~/src/synth"))
    ap.add_argument("--only", default="")
    ap.add_argument("--recorded", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rows = compare(Path(a.synth).expanduser(), set(filter(None, a.only.split(","))) or None, a.recorded)
    if a.json:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            extra = (f"ours={r['ours']} synth={r['synth']}" if "ours" in r else r.get("detail", ""))
            print(f"{r['status']:5} {r['scanner']:10} {r['language']:7} {r.get('version') or '':8} {extra}")
            for k in ("only_ours", "only_synth"):
                for x in r.get(k, [])[:5]:
                    print(f"        {k}: {x}")
    return 1 if any(r["status"] == "FAIL" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
