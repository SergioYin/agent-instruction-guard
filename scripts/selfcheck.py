"""Basic selfcheck for local smoke testing."""
from __future__ import annotations

from pathlib import Path
import json
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    safe = subprocess.run([sys.executable, "-m", "agent_instruction_guard", str(ROOT / "examples" / "safe")], cwd=ROOT, text=True, capture_output=True)
    risky = subprocess.run([sys.executable, "-m", "agent_instruction_guard", str(ROOT / "examples" / "risky"), "--fail-on", "high"], cwd=ROOT, text=True, capture_output=True)
    sarif = subprocess.run(
        [sys.executable, "-m", "agent_instruction_guard", str(ROOT / "examples" / "risky"), "--format", "sarif", "--fail-on", "none"],
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
    try:
        sarif_document = json.loads(sarif.stdout)
    except json.JSONDecodeError as exc:
        print(f"invalid SARIF JSON: {exc}")
        return 1
    if sarif_document.get("version") != "2.1.0" or not sarif_document.get("runs"):
        print("invalid SARIF document shape")
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
    print("selfcheck ok: safe example passes; risky example fails with findings; SARIF output is valid JSON; baseline suppresses findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
