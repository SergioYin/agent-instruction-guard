"""Generate deterministic sample policy and profile report fixtures."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_instruction_guard.cli import main  # noqa: E402

SAMPLE_DIR = ROOT / "examples" / "policy-override"
CONFIG_PATH = SAMPLE_DIR / "agent-instruction-guard.toml"
REPORT_PATH = ROOT / "examples" / "policy-override-report.json"
BASELINE_PATH = ROOT / "examples" / "policy-override-baseline.json"
BASELINED_REPORT_PATH = ROOT / "examples" / "policy-override-baselined-report.json"
PROFILE_COMPARISON_DIR = ROOT / "examples" / "profile-comparison"
PROFILE_COMPARISON_REPORT_PATH = ROOT / "examples" / "profile-comparison-report.json"
FIXTURE_TIMESTAMP = "2026-05-11T00:00:00Z"


def build_report_document() -> dict[str, object]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = main(
            [
                str(SAMPLE_DIR),
                "--config",
                str(CONFIG_PATH),
                "--format",
                "json",
                "--fail-on",
                "none",
            ]
        )
    if exit_code != 0:
        raise RuntimeError(f"fixture scan failed with exit code {exit_code}")
    document = json.loads(stdout.getvalue())
    document["config_path"] = CONFIG_PATH.relative_to(ROOT).as_posix()
    return document


def render_report() -> str:
    return json.dumps(build_report_document(), indent=2, sort_keys=True) + "\n"


def build_profile_comparison_document() -> dict[str, object]:
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        exit_code = main(
            [
                str(PROFILE_COMPARISON_DIR),
                "--compare-profiles",
                "--format",
                "json",
                "--fail-on",
                "none",
            ]
        )
    if exit_code != 0:
        raise RuntimeError(f"profile comparison fixture scan failed with exit code {exit_code}")
    return json.loads(stdout.getvalue())


def render_profile_comparison_report() -> str:
    return json.dumps(build_profile_comparison_document(), indent=2, sort_keys=True) + "\n"


def build_policy_override_baseline_document() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        baseline_path = Path(tmp) / "baseline.json"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    str(SAMPLE_DIR),
                    "--config",
                    str(CONFIG_PATH),
                    "--write-baseline",
                    str(baseline_path),
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )
        if exit_code != 0:
            raise RuntimeError(f"baseline fixture scan failed with exit code {exit_code}")
        document = json.loads(baseline_path.read_text(encoding="utf-8"))
    document["generated_at"] = FIXTURE_TIMESTAMP
    return document


def render_policy_override_baseline() -> str:
    return json.dumps(build_policy_override_baseline_document(), indent=2, sort_keys=True) + "\n"


def build_baselined_report_document() -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        baseline_path = Path(tmp) / "baseline.json"
        baseline_path.write_text(render_policy_override_baseline(), encoding="utf-8")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                [
                    str(SAMPLE_DIR),
                    "--config",
                    str(CONFIG_PATH),
                    "--baseline",
                    str(baseline_path),
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )
    if exit_code != 0:
        raise RuntimeError(f"baselined report fixture scan failed with exit code {exit_code}")
    document = json.loads(stdout.getvalue())
    document["config_path"] = CONFIG_PATH.relative_to(ROOT).as_posix()
    document["baseline_path"] = BASELINE_PATH.relative_to(ROOT).as_posix()
    return document


def render_baselined_report() -> str:
    return json.dumps(build_baselined_report_document(), indent=2, sort_keys=True) + "\n"


def main_script() -> int:
    REPORT_PATH.write_text(render_report(), encoding="utf-8")
    PROFILE_COMPARISON_REPORT_PATH.write_text(render_profile_comparison_report(), encoding="utf-8")
    BASELINE_PATH.write_text(render_policy_override_baseline(), encoding="utf-8")
    BASELINED_REPORT_PATH.write_text(render_baselined_report(), encoding="utf-8")
    print(f"wrote {REPORT_PATH.relative_to(ROOT).as_posix()}")
    print(f"wrote {PROFILE_COMPARISON_REPORT_PATH.relative_to(ROOT).as_posix()}")
    print(f"wrote {BASELINE_PATH.relative_to(ROOT).as_posix()}")
    print(f"wrote {BASELINED_REPORT_PATH.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_script())
