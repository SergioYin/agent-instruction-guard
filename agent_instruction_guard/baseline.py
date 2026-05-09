"""Baseline suppression support for scanner findings."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import posixpath
import re
from pathlib import Path
from typing import Iterable

from . import __version__
from .scanner import Finding

BASELINE_VERSION = 1
TOOL_NAME = "agent-instruction-guard"


class BaselineError(ValueError):
    """Raised when a baseline file cannot be loaded or validated."""


@dataclass(frozen=True)
class Baseline:
    fingerprints: frozenset[str]


def normalize_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    normalized = posixpath.normpath(normalized)
    if normalized == ".":
        return ""
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lstrip("/")


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def finding_fingerprint(finding: Finding) -> str:
    parts = [
        finding.rule,
        normalize_path(finding.path),
        str(finding.line),
        finding.severity,
        normalize_text(finding.message),
        normalize_text(finding.excerpt),
    ]
    payload = "\n".join(parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def baseline_entry(finding: Finding) -> dict[str, object]:
    return {
        "fingerprint": finding_fingerprint(finding),
        "path": normalize_path(finding.path),
        "line": finding.line,
        "severity": finding.severity,
        "rule": finding.rule,
        "message": finding.message,
        "excerpt": finding.excerpt,
    }


def baseline_document(findings: Iterable[Finding]) -> dict[str, object]:
    entries = [baseline_entry(finding) for finding in findings]
    entries.sort(key=lambda item: (str(item["path"]), int(item["line"]), str(item["rule"]), str(item["fingerprint"])))
    return {
        "version": BASELINE_VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "tool": {
            "name": TOOL_NAME,
            "version": __version__,
        },
        "entries": entries,
    }


def write_baseline(path: str | Path, findings: Iterable[Finding]) -> None:
    destination = Path(path)
    document = baseline_document(findings)
    destination.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_baseline(path: str | Path) -> Baseline:
    source = Path(path)
    try:
        raw = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"could not read baseline {source}: {exc}") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"malformed baseline JSON in {source}: {exc}") from exc
    if not isinstance(document, dict):
        raise BaselineError(f"malformed baseline {source}: top-level value must be an object")
    if document.get("version") != BASELINE_VERSION:
        raise BaselineError(f"malformed baseline {source}: version must be {BASELINE_VERSION}")
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise BaselineError(f"malformed baseline {source}: entries must be a list")
    fingerprints: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BaselineError(f"malformed baseline {source}: entries[{index}] must be an object")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise BaselineError(f"malformed baseline {source}: entries[{index}].fingerprint must be a non-empty string")
        fingerprints.add(fingerprint)
    return Baseline(frozenset(fingerprints))


def suppress_findings(findings: Iterable[Finding], baseline: Baseline | None) -> tuple[list[Finding], int]:
    items = list(findings)
    if baseline is None:
        return items, 0
    unsuppressed = [finding for finding in items if finding_fingerprint(finding) not in baseline.fingerprints]
    return unsuppressed, len(items) - len(unsuppressed)
