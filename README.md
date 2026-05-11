# Agent Instruction Guard

Scan AI-agent instruction files before Codex, Claude Code, Copilot, Cursor, Gemini, or other coding agents consume them.

`agent-instruction-guard` is a small zero-dependency Python CLI that finds risky patterns in files such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, and GitHub Copilot instruction/agent files. It is designed for repository maintainers who want a quick defensive review of the instruction layer, not a heavyweight security platform.

## Why this exists

AI coding agents increasingly rely on repository-level natural-language instructions. Those files can improve delivery quality, but they can also contain unsafe commands, accidental secrets, hidden instructions, or prompt-injection-style content. This tool gives teams a simple local check before handing a repo to an autonomous agent.

## What it detects

- Remote-download execution patterns such as `curl ... | bash`.
- Destructive command patterns such as `sudo rm -rf`.
- Possible credential exfiltration instructions involving `.env`, SSH keys, tokens, or passwords.
- Requests to bypass safety controls, approvals, guardrails, or sandboxing.
- Hidden/encoded instruction hints such as `base64 -d`, `eval(`, or “do not tell the user”.
- Likely secret material in agent-readable instruction files, with excerpts redacted.

The scanner is intentionally conservative: a finding means “review this line,” not “this repository is malicious.”

## Install

From source:

```bash
git clone https://github.com/SergioYin/agent-instruction-guard.git
cd agent-instruction-guard
python -m pip install -e .
```

Without installing, run it as a module:

```bash
python -m agent_instruction_guard --help
```

## Usage

Scan the current repository:

```bash
agent-instruction-guard .
```

Fail only on high-severity findings, the default:

```bash
agent-instruction-guard . --fail-on high
```

Emit JSON for downstream tooling:

```bash
agent-instruction-guard . --format json
```

Choose a policy profile:

```bash
agent-instruction-guard . --profile lenient
agent-instruction-guard . --profile default
agent-instruction-guard . --profile strict
```

Profiles let teams tune strictness without editing scanner rules:

- `lenient`: reduces noise by downgrading selected non-critical review findings.
- `default`: preserves the standard scanner behavior.
- `strict`: promotes risky ambiguity and scope findings for hardened contexts.

JSON output includes the selected `profile`. Findings whose severity changed also include `original_severity`.

Use repository-local rule overrides:

```bash
agent-instruction-guard . --config agent-instruction-guard.toml
```

When `--config` is not supplied, the CLI looks in the current working directory for `agent-instruction-guard.toml` and then `.agent-instruction-guard.toml`. Configuration is optional; when no config file is found, scanner behavior is unchanged.

Example config:

```toml
[rules.network_side_effect]
severity = "medium"

[rules.hidden_instruction]
severity = "ignore"
```

Supported severities are `low`, `medium`, `high`, and `ignore`. `ignore` suppresses findings for that rule. Invalid rule IDs or severities fail fast with a clear error and a non-zero exit. JSON output includes `config_path` when a config file is used, and findings whose severity changed include `original_severity`.

Configuration is a convenience for repository maintainers, not a safety boundary. Lowering severities or using `ignore` can hide risky instructions from failing scans, so keep overrides reviewed with the same care as agent instruction files. Scanner excerpts remain redacted before printing.

Sample config override evidence is checked in under `examples/policy-override/`:

```bash
python -m agent_instruction_guard examples/policy-override \
  --config examples/policy-override/agent-instruction-guard.toml \
  --format json --fail-on none
```

The matching portable fixture is `examples/policy-override-report.json`. It demonstrates `config_path` plus `original_severity` for rules promoted or downgraded by config. The fixture stores `config_path` as a repository-relative path so it can be compared across machines; the live CLI output uses an absolute path.

Regenerate the fixture after changing policy output behavior:

```bash
python scripts/generate_policy_report_fixtures.py
```

Include rule-specific remediation guidance in text or JSON reports:

```bash
agent-instruction-guard . --include-guidance
agent-instruction-guard . --format json --explain --fail-on none
```

Emit SARIF 2.1.0 for code scanning tools:

```bash
agent-instruction-guard . --format sarif --fail-on none > agent-instruction-guard.sarif
```

Include additional instruction-like files:

```bash
agent-instruction-guard . --include "docs/agent-prompts/*.md"
```

List files that would be scanned:

```bash
agent-instruction-guard . --list-files
```

List rule documentation without scanning:

```bash
agent-instruction-guard --list-rules
agent-instruction-guard --list-rules --format json
```

Create a baseline from the current findings:

```bash
agent-instruction-guard . --write-baseline .agent-instruction-guard-baseline.json --fail-on none
```

Use that baseline on later scans:

```bash
agent-instruction-guard . --baseline .agent-instruction-guard-baseline.json --fail-on high
```

This helps gradual adoption in existing repositories: known findings stay visible in the baseline file for human review, but they do not keep failing every scan while the team fixes them over time. New or changed findings still appear in the normal report and can fail the command according to `--fail-on`.

Refresh the baseline after reviewing current findings:

```bash
agent-instruction-guard . --write-baseline .agent-instruction-guard-baseline.json --fail-on none
```

## Example

Safe example:

```bash
python -m agent_instruction_guard examples/safe
```

Expected result:

```text
Agent Instruction Guard
Summary: high=0 medium=0 low=0
No risky instruction patterns found.
```

Risky example:

```bash
python -m agent_instruction_guard examples/risky --fail-on high
```

Expected result: exit code `2` and findings for hidden/bypass instructions, remote code execution, and possible credential exposure.

## Supported files

By default the CLI scans:

- `AGENTS.md` and nested `**/AGENTS.md`
- `AGENTS.override.md`
- `CLAUDE.md`
- `GEMINI.md`
- `.cursorrules`
- `.windsurfrules`
- `.github/copilot-instructions.md`
- `.github/instructions/*.instructions.md`
- `.github/agents/*.agent.md`

It skips heavy/generated directories such as `.git`, `node_modules`, `dist`, `build`, virtualenvs, and Python caches.

## Exit codes

- `0`: scan completed and no findings at or above `--fail-on` threshold.
- `2`: findings met the failure threshold.
- Findings suppressed by `--baseline` do not count toward the failure threshold.
- argparse errors use Python's standard non-zero CLI behavior.

## Local validation

```bash
python -m unittest discover -s tests -v
python scripts/selfcheck.py
git diff --check
python -m compileall agent_instruction_guard tests scripts
python -m agent_instruction_guard examples/risky --format json --fail-on none
python -m agent_instruction_guard examples/risky --format json --profile strict --fail-on none
python scripts/generate_policy_report_fixtures.py
python -m agent_instruction_guard examples/risky --format json --explain --fail-on none
python -m agent_instruction_guard examples/risky --format sarif --fail-on none
python -m agent_instruction_guard --list-rules
```

## GitHub code scanning

The SARIF output is compatible with GitHub code scanning upload workflows. This repository intentionally does not include a `.github/workflows/*` example because creating or updating workflow files requires a GitHub token with the `workflow` scope.

## Non-goals

- It does not execute or sandbox agent instructions.
- It does not replace human review, dependency scanning, or secret-scanning tools.
- It does not claim that every flagged line is malicious.
- It does not modify files automatically.

## License

MIT
