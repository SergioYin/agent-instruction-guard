"""Scanner for AI-agent instruction files.

The goal is not to prove maliciousness. It highlights risky natural-language
or shell patterns that deserve human review before an agent consumes the file.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import fnmatch
import json
import re
from typing import Iterable, Iterator

INSTRUCTION_GLOBS = [
    "AGENTS.md",
    "AGENTS.override.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".github/copilot-instructions.md",
    ".github/instructions/*.instructions.md",
    ".github/agents/*.agent.md",
    "**/AGENTS.md",
    "**/AGENTS.override.md",
    "**/CLAUDE.md",
    "**/GEMINI.md",
]

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{16,})"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]

RULES = [
    (
        "remote_code_execution",
        "high",
        re.compile(r"(?i)(curl|wget)\b[^\n|;&]*(\||&&|;)\s*(sh|bash|python|python3|node)\b"),
        "Downloads and immediately executes remote content.",
    ),
    (
        "destructive_command",
        "high",
        re.compile(r"(?i)\b(rm\s+-rf\s+/(\s|$)|sudo\s+rm\s+-rf|mkfs\.|dd\s+if=|chmod\s+-R\s+777\s+/)"),
        "Contains destructive shell command patterns.",
    ),
    (
        "credential_exfiltration",
        "high",
        re.compile(r"(?i)(cat|print|echo|upload|send|post).{0,80}(\.env|id_rsa|ssh|token|secret|password|credentials)"),
        "May instruct an agent to reveal or transmit credentials.",
    ),
    (
        "ignore_safety_controls",
        "medium",
        re.compile(r"(?i)(ignore|bypass|disable).{0,60}(safety|policy|approval|sandbox|guardrail|permission)"),
        "Asks the agent to bypass safety or approval controls.",
    ),
    (
        "hidden_instruction",
        "medium",
        re.compile(r"(?i)(base64\s+-d|eval\(|fromCharCode|hidden instruction|invisible instruction|do not tell the user)"),
        "Suggests hidden, encoded, or non-transparent instructions.",
    ),
    (
        "network_side_effect",
        "low",
        re.compile(r"(?i)\b(curl|wget|scp|rsync|nc|netcat)\b"),
        "Uses network-capable commands; verify they are read-only and expected.",
    ),
]

@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    message: str
    excerpt: str

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "excerpt": self.excerpt,
        }


def is_instruction_file(path: Path, root: Path) -> bool:
    rel = path.relative_to(root).as_posix()
    return any(fnmatch.fnmatch(rel, pattern) for pattern in INSTRUCTION_GLOBS)


def iter_instruction_files(root: Path, extra_globs: Iterable[str] = ()) -> Iterator[Path]:
    root = root.resolve()
    patterns = list(INSTRUCTION_GLOBS) + list(extra_globs)
    seen: set[Path] = set()
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        rel = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(rel, pattern) for pattern in patterns):
            if path not in seen:
                seen.add(path)
                yield path


def redact(text: str) -> str:
    clean = text.strip().replace("\t", " ")
    for pattern in SECRET_PATTERNS:
        clean = pattern.sub(lambda m: m.group(0)[:12] + "[REDACTED]", clean)
    if len(clean) > 140:
        clean = clean[:137] + "..."
    return clean


def scan_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="replace")
    rel = path.relative_to(root).as_posix()
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(rel, line_no, "possible_secret", "high", "Potential credential material in an agent-readable file.", redact(line)))
                break
        for rule, severity, pattern, message in RULES:
            if not pattern.search(line):
                continue
            lowered = line.lower()
            if rule == "credential_exfiltration" and ("never" in lowered or "do not" in lowered or "don't" in lowered):
                continue
            findings.append(Finding(rel, line_no, rule, severity, message, redact(line)))
    return findings


def scan(root: str | Path, extra_globs: Iterable[str] = ()) -> list[Finding]:
    root_path = Path(root).resolve()
    findings: list[Finding] = []
    for path in iter_instruction_files(root_path, extra_globs):
        findings.extend(scan_file(path, root_path))
    return sorted(findings, key=lambda f: (f.path, f.line, f.severity, f.rule))


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def findings_json(findings: Iterable[Finding]) -> str:
    items = [finding.as_dict() for finding in findings]
    return json.dumps({"findings": items, "summary": summarize(items_to_findings(items))}, indent=2, sort_keys=True)


def items_to_findings(items: Iterable[dict[str, object]]) -> Iterator[Finding]:
    for item in items:
        yield Finding(
            path=str(item["path"]),
            line=int(item["line"]),
            rule=str(item["rule"]),
            severity=str(item["severity"]),
            message=str(item["message"]),
            excerpt=str(item["excerpt"]),
        )
