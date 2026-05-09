"""SARIF serialization for scanner findings."""
from __future__ import annotations

import json
from typing import Iterable

from . import __version__
from .scanner import Finding, RULES

INFORMATION_URI = "https://github.com/SergioYin/agent-instruction-guard"

SEVERITY_TO_LEVEL = {
    "error": "error",
    "high": "error",
    "warning": "warning",
    "medium": "warning",
    "info": "note",
    "low": "note",
}


def _rule_messages() -> dict[str, str]:
    messages = {
        "possible_secret": "Potential credential material in an agent-readable file.",
    }
    for rule_id, _severity, _pattern, message in RULES:
        messages[rule_id] = message
    return messages


def sarif_dict(findings: Iterable[Finding]) -> dict[str, object]:
    items = list(findings)
    rule_messages = _rule_messages()
    rule_ids = sorted({finding.rule for finding in items})
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": rule_messages.get(rule_id, rule_id.replace("_", " "))},
        }
        for rule_id in rule_ids
    ]
    results = []
    for finding in items:
        result = {
            "ruleId": finding.rule,
            "level": SEVERITY_TO_LEVEL.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.path},
                        "region": {
                            "startLine": finding.line,
                            "snippet": {"text": finding.excerpt},
                        },
                    }
                }
            ],
        }
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-instruction-guard",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def findings_sarif(findings: Iterable[Finding]) -> str:
    return json.dumps(sarif_dict(findings), indent=2, sort_keys=True)
