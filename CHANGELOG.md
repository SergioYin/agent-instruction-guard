# Changelog

## 0.1.6

- Added checked-in sample policy override inputs and a portable JSON report fixture.
- Added deterministic fixture generation and tests for config override evidence fields.
- Documented how to regenerate and inspect config override report evidence.

## 0.1.5

- Added repository-local TOML configuration via `--config` or auto-discovered `agent-instruction-guard.toml` / `.agent-instruction-guard.toml`.
- Added per-rule severity overrides, including `ignore` to suppress a rule.
- Added JSON `config_path` metadata when configuration is used.

## 0.1.4

- Added policy profiles with `--profile {lenient,default,strict}`.
- Added JSON report metadata for the selected profile and per-finding `original_severity` when a profile changes severity.

## 0.1.3

- Added `--include-guidance` / `--explain` to include concise remediation guidance in text and JSON reports.
- Added `--list-rules` to print rule documentation without scanning a repository.
- Added SARIF rule help/properties metadata with rule guidance.
- Updated tests and runnable README examples for guidance and rule documentation.

## 0.1.2

- Added baseline support for suppressing known findings while keeping new findings visible.
- Added SARIF output for code scanning tools.
