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

Include additional instruction-like files:

```bash
agent-instruction-guard . --include "docs/agent-prompts/*.md"
```

List files that would be scanned:

```bash
agent-instruction-guard . --list-files
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
- argparse errors use Python's standard non-zero CLI behavior.

## Local validation

```bash
python -m unittest discover -s tests -v
python scripts/selfcheck.py
python -m agent_instruction_guard examples/risky --format json --fail-on none
```

## Non-goals

- It does not execute or sandbox agent instructions.
- It does not replace human review, dependency scanning, or secret-scanning tools.
- It does not claim that every flagged line is malicious.
- It does not modify files automatically.

## License

MIT
