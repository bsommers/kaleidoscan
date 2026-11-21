"""T-PARITY: adapter findings == Synth's own invocation of the same scanner on the same corpus.

Reference = fresh run of Synth's commands (scripts/parity.py), so stale recordings cannot
mask or cause diffs. Skips (with reason) when Synth, its corpus or a scanner is unavailable.
CodeQL parity is not covered here (heavy, license-gated).
"""
import importlib.util
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

SYNTH = Path(os.environ.get("SYNTH_DIR", "~/src/synth")).expanduser()
_spec = importlib.util.spec_from_file_location(
    "kscan_parity", Path(__file__).resolve().parents[2] / "scripts" / "parity.py")
parity = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(parity)


@pytest.fixture(scope="module")
def rows():
    if not (SYNTH / "corpus").is_dir():
        pytest.skip(f"Synth corpus not found at {SYNTH} (set SYNTH_DIR)")
    return parity.compare(SYNTH, None)


@pytest.mark.parametrize("scanner,lang", [(s, l) for s, l, _, _ in parity.PAIRS])
def test_parity(rows, scanner, lang):
    row = next(r for r in rows if r["scanner"] == scanner and r["language"] == lang)
    if row["status"] == "SKIP":
        pytest.skip(f"{scanner}/{lang}: {row['detail']}")
    assert row["status"] == "PASS", (row.get("detail"), row.get("only_ours"), row.get("only_synth"))
    assert row["ours"] > 0  # a vacuous 0 == 0 would prove nothing
