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

@dataclass(frozen=True)
class RuleDoc:
    rule: str
    severity: str
    message: str
    guidance: dict[str, str]

    def as_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "guidance": dict(self.guidance),
        }


RULE_GUIDANCE = {
    "remote_code_execution": {
        "why": "Piping downloaded content into an interpreter lets remote changes run with local privileges.",
        "rewrite": "Download to a reviewed file, verify its checksum or signature, then run an audited command.",
        "verify": "Confirm the URL, pinned version, checksum, and required shell privileges.",
    },
    "destructive_command": {
        "why": "Recursive deletes, disk writes, or broad permission changes can destroy project or host data.",
        "rewrite": "Scope cleanup commands to known generated paths and require an explicit human approval step.",
        "verify": "Check the target path, dry-run output, backups, and whether sudo is actually required.",
    },
    "credential_exfiltration": {
        "why": "Agent-readable instructions that print or send credentials can leak private access material.",
        "rewrite": "Tell agents to avoid reading secrets and use approved secret managers or redacted diagnostics.",
        "verify": "Confirm logs, issues, pull requests, and uploaded artifacts do not contain credential values.",
    },
    "ignore_safety_controls": {
        "why": "Bypass instructions can pressure agents to ignore sandboxing, approval, or policy boundaries.",
        "rewrite": "State the legitimate workflow and require normal approvals for privileged or risky actions.",
        "verify": "Confirm the instruction does not conflict with repository, tool, or organization policies.",
    },
    "hidden_instruction": {
        "why": "Hidden or encoded directions make review harder and can conceal behavior from maintainers.",
        "rewrite": "Replace encoded or non-transparent instructions with plain, reviewable text.",
        "verify": "Decode any payloads and confirm the visible instruction matches the intended agent behavior.",
    },
    "network_side_effect": {
        "why": "Network-capable commands can fetch unreviewed content or transmit repository data.",
        "rewrite": "Prefer pinned, read-only fetches and document the expected destination and data flow.",
        "verify": "Confirm the endpoint, method, authentication, and whether any local data is uploaded.",
    },
    "possible_secret": {
        "why": "Instruction files are commonly shared with agents and logs, so embedded secrets can spread quickly.",
        "rewrite": "Remove the value, rotate it if it was real, and reference an environment variable or secret store.",
        "verify": "Confirm the secret is revoked or rotated and that history, logs, and baselines are clean.",
    },
}

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

PROFILES = ("lenient", "default", "strict")

PROFILE_SEVERITY_OVERRIDES = {
    "lenient": {
        "ignore_safety_controls": "low",
    },
    "default": {},
    "strict": {
        "ignore_safety_controls": "high",
        "hidden_instruction": "high",
        "network_side_effect": "medium",
    },
}

RULE_DOCS = {
    "possible_secret": RuleDoc(
        "possible_secret",
        "high",
        "Potential credential material in an agent-readable file.",
        RULE_GUIDANCE["possible_secret"],
    )
}
for _rule, _severity, _pattern, _message in RULES:
    RULE_DOCS[_rule] = RuleDoc(_rule, _severity, _message, RULE_GUIDANCE[_rule])


def rule_docs() -> list[RuleDoc]:
    severity_rank = {"high": 3, "medium": 2, "low": 1}
    return sorted(RULE_DOCS.values(), key=lambda doc: (-severity_rank.get(doc.severity, 0), doc.rule))

@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    message: str
    excerpt: str
    original_severity: str | None = None

    def as_dict(self, include_guidance: bool = False) -> dict[str, object]:
        item: dict[str, object] = {
            "path": self.path,
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "excerpt": self.excerpt,
        }
        if self.original_severity is not None:
            item["original_severity"] = self.original_severity
        if include_guidance:
            doc = RULE_DOCS.get(self.rule)
            if doc is not None:
                item["guidance"] = dict(doc.guidance)
        return item


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


def apply_profile(findings: Iterable[Finding], profile: str) -> list[Finding]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile: {profile}")
    overrides = PROFILE_SEVERITY_OVERRIDES[profile]
    profiled: list[Finding] = []
    for finding in findings:
        severity = overrides.get(finding.rule, finding.severity)
        original = finding.original_severity
        if severity != finding.severity:
            original = finding.original_severity or finding.severity
        profiled.append(
            Finding(
                path=finding.path,
                line=finding.line,
                rule=finding.rule,
                severity=severity,
                message=finding.message,
                excerpt=finding.excerpt,
                original_severity=original,
            )
        )
    return sorted(profiled, key=lambda f: (f.path, f.line, f.severity, f.rule))


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
            original_severity=str(item["original_severity"]) if item.get("original_severity") is not None else None,
        )
