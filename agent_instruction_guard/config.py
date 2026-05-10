"""Repository-local configuration for agent-instruction-guard."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ast

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python < 3.11
    tomllib = None  # type: ignore[assignment]

CONFIG_FILENAMES = ("agent-instruction-guard.toml", ".agent-instruction-guard.toml")
VALID_SEVERITIES = {"low", "medium", "high", "ignore"}


class ConfigError(ValueError):
    """Raised when configuration is malformed or unsafe to apply."""


@dataclass(frozen=True)
class GuardConfig:
    path: Path
    rule_severities: dict[str, str]


def discover_config(cwd: Path | None = None) -> Path | None:
    root = (cwd or Path.cwd()).resolve()
    for filename in CONFIG_FILENAMES:
        candidate = root / filename
        if candidate.is_file():
            return candidate
    return None


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            continue
        if char == "#" and quote is None:
            return line[:index]
    return line


def _parse_value(raw: str) -> object:
    raw = raw.strip()
    if raw in {"true", "false"}:
        return raw == "true"
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_parse_value(part) for part in inner.split(",") if part.strip()]
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        try:
            value = ast.literal_eval(raw)
        except (SyntaxError, ValueError) as exc:
            raise ConfigError(f"invalid TOML string value: {raw}") from exc
        if not isinstance(value, str):
            raise ConfigError(f"invalid TOML string value: {raw}")
        return value
    raise ConfigError(f"unsupported TOML value: {raw}")


def _parse_tiny_toml(text: str) -> dict[str, object]:
    document: dict[str, object] = {}
    current: dict[str, object] = document
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if not section:
                raise ConfigError(f"invalid empty TOML section on line {line_no}")
            current = document
            for part in section.split("."):
                if not part:
                    raise ConfigError(f"invalid TOML section on line {line_no}")
                next_section = current.setdefault(part, {})
                if not isinstance(next_section, dict):
                    raise ConfigError(f"TOML section conflicts with value on line {line_no}")
                current = next_section
            continue
        if "=" not in line:
            raise ConfigError(f"invalid TOML syntax on line {line_no}")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise ConfigError(f"invalid empty TOML key on line {line_no}")
        current[key] = _parse_value(raw_value)
    return document


def _loads_toml(text: str) -> dict[str, object]:
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML: {exc}") from exc
    return _parse_tiny_toml(text)


def load_config(path: str | Path, valid_rule_ids: set[str]) -> GuardConfig:
    config_path = Path(path).expanduser().resolve()
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read config {config_path}: {exc}") from exc
    document = _loads_toml(text)
    rules = document.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError("config [rules] must be a table")
    overrides: dict[str, str] = {}
    for rule_id, body in rules.items():
        if rule_id not in valid_rule_ids:
            raise ConfigError(f"unknown rule id in config: {rule_id}")
        if not isinstance(body, dict):
            raise ConfigError(f"config [rules.{rule_id}] must be a table")
        unknown_keys = sorted(set(body) - {"severity"})
        if unknown_keys:
            raise ConfigError(f"unknown key in [rules.{rule_id}]: {unknown_keys[0]}")
        severity = body.get("severity")
        if not isinstance(severity, str):
            raise ConfigError(f"[rules.{rule_id}] severity must be a string")
        if severity not in VALID_SEVERITIES:
            allowed = ", ".join(sorted(VALID_SEVERITIES))
            raise ConfigError(f"invalid severity for rule {rule_id}: {severity} (expected one of: {allowed})")
        overrides[rule_id] = severity
    return GuardConfig(path=config_path, rule_severities=overrides)
