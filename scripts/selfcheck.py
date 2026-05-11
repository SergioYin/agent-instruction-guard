"""Basic selfcheck for local smoke testing."""
from __future__ import annotations

from pathlib import Path
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.generate_policy_report_fixtures import (  # noqa: E402
    render_baselined_report,
    render_policy_override_baseline,
    render_profile_comparison_report,
    render_report,
)


def main() -> int:
    safe = subprocess.run([sys.executable, "-m", "agent_instruction_guard", str(ROOT / "examples" / "safe")], cwd=ROOT, text=True, capture_output=True)
    risky = subprocess.run([sys.executable, "-m", "agent_instruction_guard", str(ROOT / "examples" / "risky"), "--fail-on", "high"], cwd=ROOT, text=True, capture_output=True)
    sarif = subprocess.run(
        [sys.executable, "-m", "agent_instruction_guard", str(ROOT / "examples" / "risky"), "--format", "sarif", "--fail-on", "none"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    strict_json = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_instruction_guard",
            str(ROOT / "examples" / "risky"),
            "--format",
            "json",
            "--profile",
            "strict",
            "--fail-on",
            "none",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    profile_comparison = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_instruction_guard",
            str(ROOT / "examples" / "profile-comparison"),
            "--compare-profiles",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    if safe.returncode != 0:
        print(safe.stdout)
        print(safe.stderr)
        return safe.returncode
    if risky.returncode != 2:
        print(risky.stdout)
        print(risky.stderr)
        return 1
    if sarif.returncode != 0:
        print(sarif.stdout)
        print(sarif.stderr)
        return sarif.returncode
    if strict_json.returncode != 0:
        print(strict_json.stdout)
        print(strict_json.stderr)
        return strict_json.returncode
    if profile_comparison.returncode != 0:
        print(profile_comparison.stdout)
        print(profile_comparison.stderr)
        return profile_comparison.returncode
    try:
        sarif_document = json.loads(sarif.stdout)
    except json.JSONDecodeError as exc:
        print(f"invalid SARIF JSON: {exc}")
        return 1
    if sarif_document.get("version") != "2.1.0" or not sarif_document.get("runs"):
        print("invalid SARIF document shape")
        return 1
    try:
        strict_document = json.loads(strict_json.stdout)
    except json.JSONDecodeError as exc:
        print(f"invalid strict profile JSON: {exc}")
        return 1
    if strict_document.get("profile") != "strict":
        print("strict profile missing from JSON output")
        return 1
    if not any("original_severity" in finding for finding in strict_document.get("findings", [])):
        print("strict profile did not report changed original severity")
        return 1
    try:
        comparison_document = json.loads(profile_comparison.stdout)
    except json.JSONDecodeError as exc:
        print(f"invalid profile comparison JSON: {exc}")
        return 1
    profiles = comparison_document.get("profiles", {})
    if sorted(profiles) != ["default", "lenient", "strict"]:
        print("profile comparison did not include all profiles")
        return 1
    if profiles["strict"].get("summary", {}).get("high") != 2:
        print("profile comparison strict summary did not show promoted findings")
        return 1
    fixture_path = ROOT / "examples" / "policy-override-report.json"
    if render_report() != fixture_path.read_text(encoding="utf-8"):
        print("policy override report fixture is stale; run python scripts/generate_policy_report_fixtures.py")
        return 1
    profile_fixture_path = ROOT / "examples" / "profile-comparison-report.json"
    if render_profile_comparison_report() != profile_fixture_path.read_text(encoding="utf-8"):
        print("profile comparison report fixture is stale; run python scripts/generate_policy_report_fixtures.py")
        return 1
    baseline_fixture_path = ROOT / "examples" / "policy-override-baseline.json"
    if render_policy_override_baseline() != baseline_fixture_path.read_text(encoding="utf-8"):
        print("policy override baseline fixture is stale; run python scripts/generate_policy_report_fixtures.py")
        return 1
    baselined_report_fixture_path = ROOT / "examples" / "policy-override-baselined-report.json"
    if render_baselined_report() != baselined_report_fixture_path.read_text(encoding="utf-8"):
        print("policy override baselined report fixture is stale; run python scripts/generate_policy_report_fixtures.py")
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        baseline_path = Path(tmp) / "baseline.json"
        write_baseline = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_instruction_guard",
                str(ROOT / "examples" / "risky"),
                "--write-baseline",
                str(baseline_path),
                "--fail-on",
                "none",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        use_baseline = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_instruction_guard",
                str(ROOT / "examples" / "risky"),
                "--baseline",
                str(baseline_path),
                "--fail-on",
                "high",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if write_baseline.returncode != 0:
            print(write_baseline.stdout)
            print(write_baseline.stderr)
            return write_baseline.returncode
        if use_baseline.returncode != 0:
            print(use_baseline.stdout)
            print(use_baseline.stderr)
            return use_baseline.returncode
        if "Suppressed by baseline:" not in use_baseline.stdout:
            print(use_baseline.stdout)
            print("baseline suppression count missing")
            return 1
    print("selfcheck ok: safe example passes; risky example fails with findings; SARIF, strict-profile JSON, profile comparison, policy fixtures, and baseline suppression are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
