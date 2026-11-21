#!/usr/bin/env bash
# Tiered verification. Usage:
#   scripts/verify.sh --tier smoke|unit|integration|system|security|perf|stress|torture
#   scripts/verify.sh --only <tier>[/<pytest -k expr>]
#   scripts/verify.sh            # default tiers: smoke unit integration system security
#   scripts/verify.sh --all      # default tiers + perf stress torture
# Prints "<tier>: PASS n / SKIP m / FAIL k" and lists every SKIP reason. Exit 1 on any FAIL.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Keep venvs/caches/bytecode off /tmp and out of the repo.
export UV_PROJECT_ENVIRONMENT="${UV_PROJECT_ENVIRONMENT:-/datanapps/venvs/kaleidoscan}"
export UV_CACHE_DIR="${UV_CACHE_DIR:-/datanapps/cache/uv}"
CACHE_BASE="${KALEIDOSCAN_CACHE:-/datanapps/cache/kaleidoscan}"
export PYTHONPYCACHEPREFIX="$CACHE_BASE/pycache"
mkdir -p "$CACHE_BASE"

DEFAULT_TIERS=(smoke unit integration system security)
ALL_TIERS=(smoke unit integration system security perf stress torture)
tiers=("${DEFAULT_TIERS[@]}")
kexpr=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) tiers=("$2"); shift 2 ;;
    --only) tiers=("${2%%/*}"); [[ "$2" == */* ]] && kexpr="${2#*/}"; shift 2 ;;
    --all) tiers=("${ALL_TIERS[@]}"); shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
for t in "${tiers[@]}"; do
  [[ " ${ALL_TIERS[*]} " == *" $t "* ]] || { echo "unknown tier: $t" >&2; exit 2; }
done

uv sync --quiet || { echo "uv sync failed" >&2; exit 4; }

total_fail=0
for t in "${tiers[@]}"; do
  junit="$CACHE_BASE/junit-$t.xml"
  args=(-m "$t" -q -p no:cacheprovider --junitxml="$junit")
  [[ -n "$kexpr" ]] && args+=(-k "$kexpr")
  out="$(uv run --quiet pytest "${args[@]}" 2>&1)"; rc=$?
  if [[ $rc -ne 0 && $rc -ne 5 ]]; then echo "$out" | tail -40; fi
  # rc 5 = no tests collected in this tier: reported honestly as 0/0/0.
  python3 - "$junit" "$t" <<'PY'
import sys, xml.etree.ElementTree as ET
path, tier = sys.argv[1:3]
try:
    root = ET.parse(path).getroot()
except Exception:
    print(f"{tier}: PASS 0 / SKIP 0 / FAIL 0  (no tests collected)"); sys.exit(0)
p = s = f = 0; skips = []
for tc in root.iter("testcase"):
    if tc.find("skipped") is not None:
        s += 1; skips.append((tc.get("classname","")+"::"+tc.get("name",""), tc.find("skipped").get("message","")))
    elif tc.find("failure") is not None or tc.find("error") is not None:
        f += 1
    else:
        p += 1
print(f"{tier}: PASS {p} / SKIP {s} / FAIL {f}")
for n, m in skips: print(f"  SKIP {n}: {m}")
PY
  [[ $rc -ne 0 && $rc -ne 5 ]] && total_fail=1
  rm -f "$junit"
done
exit $total_fail
