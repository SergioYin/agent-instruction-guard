"""Command-line interface for agent-instruction-guard."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .baseline import BaselineError, load_baseline, suppress_findings, write_baseline
from .config import ConfigError, discover_config, load_config
from .sarif import findings_sarif
from .scanner import PROFILES, RULE_DOCS, apply_profile, apply_rule_overrides, rule_docs, scan, summarize

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-instruction-guard",
        description="Scan AI agent instruction files for risky commands, prompt-injection patterns, and accidental secrets.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository or directory to scan (default: current directory).")
    parser.add_argument("--include", action="append", default=[], help="Additional glob for instruction-like files. Can be repeated.")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text", help="Output format.")
    parser.add_argument("--profile", choices=PROFILES, default="default", help="Policy profile: lenient reduces selected non-critical findings, default preserves normal behavior, strict promotes risky ambiguity/scope findings.")
    parser.add_argument("--config", help="Path to agent-instruction-guard TOML config. Defaults to auto-discovery in the current working directory.")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high", help="Exit non-zero when findings at or above this severity exist. Default: high.")
    parser.add_argument("--baseline", help="Suppress findings whose stable fingerprints appear in this JSON baseline.")
    parser.add_argument("--write-baseline", help="Write a JSON baseline for the current findings without suppressing them.")
    parser.add_argument("--compare-profiles", action="store_true", help="Report lenient, default, and strict policy results for the same scan.")
    parser.add_argument("--list-files", action="store_true", help="List discovered instruction files and exit.")
    parser.add_argument("--list-rules", action="store_true", help="List scanner rule documentation and exit without scanning.")
    parser.add_argument("--include-guidance", "--explain", action="store_true", help="Include rule-specific remediation guidance in reports.")
    return parser


def _discovered_files(path: Path, include: list[str]) -> list[str]:
    from .scanner import iter_instruction_files

    root = path.resolve()
    return [p.relative_to(root).as_posix() for p in iter_instruction_files(root, include)]


def _print_guidance(guidance: dict[str, str], indent: str = "  ") -> None:
    print(f"{indent}Guidance:")
    print(f"{indent}  Why: {guidance['why']}")
    print(f"{indent}  Rewrite: {guidance['rewrite']}")
    print(f"{indent}  Verify: {guidance['verify']}")


def _print_rule_docs_text() -> None:
    print("Agent Instruction Guard Rules")
    for doc in rule_docs():
        print("")
        print(f"[{doc.severity.upper()}] {doc.rule}")
        print(f"  {doc.message}")
        _print_guidance(doc.guidance)


def _print_text(findings, suppressed_count: int = 0, show_suppressed: bool = False, include_guidance: bool = False) -> None:
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
        if include_guidance:
            doc = RULE_DOCS.get(finding.rule)
            if doc is not None:
                _print_guidance(doc.guidance)


def _should_fail(findings, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[f.severity] >= threshold for f in findings)


def _apply_policy(findings, profile: str, config):
    policy_findings = apply_profile(findings, profile)
    if config is not None:
        policy_findings = apply_rule_overrides(policy_findings, config.rule_severities)
    return policy_findings


def _json_report(profile: str, findings, suppressed_count: int, include_guidance: bool) -> dict[str, object]:
    return {
        "profile": profile,
        "summary": summarize(findings),
        "suppressed": suppressed_count,
        "findings": [f.as_dict(include_guidance=include_guidance) for f in findings],
    }


def _print_profile_comparison_text(profile_reports: dict[str, dict[str, object]]) -> None:
    print("Agent Instruction Guard Profile Comparison")
    for profile in PROFILES:
        report = profile_reports[profile]
        counts = report["summary"]
        print(
            f"{profile}: high={counts.get('high', 0)} "
            f"medium={counts.get('medium', 0)} low={counts.get('low', 0)} "
            f"suppressed={report['suppressed']}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.compare_profiles and args.write_baseline:
        parser.error("--compare-profiles cannot be combined with --write-baseline")
    if args.compare_profiles and args.format == "sarif":
        parser.error("--compare-profiles supports text and json formats")
    if args.list_rules:
        if args.format == "json":
            print(json.dumps({"rules": [doc.as_dict() for doc in rule_docs()]}, indent=2, sort_keys=True))
        else:
            _print_rule_docs_text()
        return 0
    root = Path(args.path)
    if not root.exists():
        parser.error(f"path does not exist: {root}")
    if args.list_files:
        for rel in _discovered_files(root, args.include):
            print(rel)
        return 0
    config_path = Path(args.config).expanduser() if args.config else discover_config()
    config = None
    if config_path is not None:
        try:
            config = load_config(config_path, set(RULE_DOCS))
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    scanned_findings = scan(root, args.include)
    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if args.compare_profiles:
        profile_reports: dict[str, dict[str, object]] = {}
        visible_by_profile = {}
        for profile in PROFILES:
            profile_findings = _apply_policy(scanned_findings, profile, config)
            visible_findings, suppressed_count = suppress_findings(profile_findings, baseline)
            visible_by_profile[profile] = visible_findings
            profile_reports[profile] = _json_report(profile, visible_findings, suppressed_count, args.include_guidance)
        if args.format == "json":
            report: dict[str, object] = {"profiles": profile_reports}
            if config is not None:
                report["config_path"] = str(config.path)
            if args.baseline:
                report["baseline_path"] = str(Path(args.baseline).expanduser().resolve())
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            _print_profile_comparison_text(profile_reports)
        fail_findings = [finding for findings in visible_by_profile.values() for finding in findings]
        return 2 if _should_fail(fail_findings, args.fail_on) else 0
    findings = _apply_policy(scanned_findings, args.profile, config)
    visible_findings, suppressed_count = suppress_findings(findings, baseline)
    if args.write_baseline:
        try:
            write_baseline(args.write_baseline, findings)
        except OSError as exc:
            print(f"error: could not write baseline {args.write_baseline}: {exc}", file=sys.stderr)
            return 1
    if args.format == "json":
        report = {
            "profile": args.profile,
            "summary": summarize(visible_findings),
            "suppressed": suppressed_count,
            "findings": [f.as_dict(include_guidance=args.include_guidance) for f in visible_findings],
        }
        if config is not None:
            report["config_path"] = str(config.path)
        if args.baseline:
            report["baseline_path"] = str(Path(args.baseline).expanduser().resolve())
        print(
            json.dumps(
                report,
                indent=2,
                sort_keys=True,
            )
        )
    elif args.format == "sarif":
        print(findings_sarif(visible_findings))
    else:
        _print_text(visible_findings, suppressed_count, baseline is not None, args.include_guidance)
    return 2 if _should_fail(visible_findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
