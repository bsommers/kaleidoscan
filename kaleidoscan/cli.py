"""kaleidoscan CLI (C5). Exit codes: 0 ok · 1 gate failed · 2 usage/config · 3 required scanner missing · 4 internal."""
from __future__ import annotations

import argparse
import sys

from kaleidoscan import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kaleidoscan", description="Composable security-testing pipeline.")
    p.add_argument("--version", action="version", version=f"kaleidoscan {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")
    d = sub.add_parser("doctor", help="report scanner tool availability and versions")
    d.add_argument("--json", action="store_true", help="emit only JSON on stdout")
    d.add_argument("--strict", action="store_true", help="exit 3 if a required scanner is missing")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:  # argparse: 0 for --help/--version, 2 for usage errors
        return int(e.code or 0)
    if args.command is None:
        parser.print_usage(sys.stderr)
        return 2
    try:
        if args.command == "doctor":
            from kaleidoscan import doctor

            return doctor.run(as_json=args.json, strict=args.strict)
    except Exception as e:  # noqa: BLE001 - top-level boundary maps to exit 4
        print(f"internal error: {type(e).__name__}: {e}", file=sys.stderr)
        return 4
    return 2
