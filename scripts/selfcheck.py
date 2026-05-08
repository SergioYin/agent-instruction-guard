"""Basic selfcheck for local smoke testing."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    safe = subprocess.run([sys.executable, "-m", "agent_instruction_guard", str(ROOT / "examples" / "safe")], cwd=ROOT, text=True, capture_output=True)
    risky = subprocess.run([sys.executable, "-m", "agent_instruction_guard", str(ROOT / "examples" / "risky"), "--fail-on", "high"], cwd=ROOT, text=True, capture_output=True)
    if safe.returncode != 0:
        print(safe.stdout)
        print(safe.stderr)
        return safe.returncode
    if risky.returncode != 2:
        print(risky.stdout)
        print(risky.stderr)
        return 1
    print("selfcheck ok: safe example passes; risky example fails with findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
