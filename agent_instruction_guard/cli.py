"""Command-line interface for agent-instruction-guard."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .baseline import BaselineError, load_baseline, suppress_findings, write_baseline
from .sarif import findings_sarif
from .scanner import scan, summarize

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-instruction-guard",
        description="Scan AI agent instruction files for risky commands, prompt-injection patterns, and accidental secrets.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository or directory to scan (default: current directory).")
    parser.add_argument("--include", action="append", default=[], help="Additional glob for instruction-like files. Can be repeated.")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format.")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high", help="Exit non-zero when findings at or above this severity exist. Default: high.")
    parser.add_argument("--baseline", help="Suppress findings whose stable fingerprints appear in this JSON baseline.")
    parser.add_argument("--write-baseline", help="Write a JSON baseline for the current findings without suppressing them.")
    parser.add_argument("--list-files", action="store_true", help="List discovered instruction files and exit.")
    return parser


def _discovered_files(path: Path, include: list[str]) -> list[str]:
    from .scanner import iter_instruction_files

    root = path.resolve()
    return [p.relative_to(root).as_posix() for p in iter_instruction_files(root, include)]


def _print_text(findings, suppressed_count: int = 0, show_suppressed: bool = False) -> None:
    counts = summarize(findings)
    print("Agent Instruction Guard")
    print(f"Summary: high={counts.get('high', 0)} medium={counts.get('medium', 0)} low={counts.get('low', 0)}")
    if show_suppressed:
        print(f"Suppressed by baseline: {suppressed_count}")
    if not findings:
        print("No risky instruction patterns found.")
        return
    print("")
    for finding in findings:
        print(f"[{finding.severity.upper()}] {finding.path}:{finding.line} {finding.rule}")
        print(f"  {finding.message}")
        print(f"  > {finding.excerpt}")


def _should_fail(findings, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[f.severity] >= threshold for f in findings)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        parser.error(f"path does not exist: {root}")
    if args.list_files:
        for rel in _discovered_files(root, args.include):
            print(rel)
        return 0
    findings = scan(root, args.include)
    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    visible_findings, suppressed_count = suppress_findings(findings, baseline)
    if args.write_baseline:
        try:
            write_baseline(args.write_baseline, findings)
        except OSError as exc:
            print(f"error: could not write baseline {args.write_baseline}: {exc}", file=sys.stderr)
            return 1
    if args.format == "json":
        print(json.dumps({"summary": summarize(visible_findings), "suppressed": suppressed_count, "findings": [f.as_dict() for f in visible_findings]}, indent=2, sort_keys=True))
    elif args.format == "sarif":
        print(findings_sarif(visible_findings))
    else:
        _print_text(visible_findings, suppressed_count, baseline is not None)
    return 2 if _should_fail(visible_findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
