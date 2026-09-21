from pathlib import Path
from typing import Any, Dict, List, Union

import yaml

from cloudshield.engine.evaluator import SUPPORTED_OPERATORS
from cloudshield.models import DetectionRule

CONDITION_KEYS = {"field", "operator", "value"}


def validate_conditions(rule_id: str, conditions: List[Any]) -> None:
    """Fail fast on malformed conditions so bad rules never lie dormant."""
    for index, condition in enumerate(conditions):
        if not isinstance(condition, dict) or not condition:
            raise ValueError(
                f"Invalid condition #{index} in {rule_id}: "
                f"expected non-empty mapping, got {condition!r}"
            )
        field = condition.get("field")
        label = field if isinstance(field, str) and field else f"condition #{index}"
        prefix = f"Invalid condition in {rule_id} for {label}"
        if not isinstance(field, str) or not field:
            raise ValueError(f"{prefix}: missing or non-string 'field' in {condition!r}")
        extra = set(condition) - CONDITION_KEYS
        if extra:
            raise ValueError(
                f"{prefix}: unexpected keys {sorted(map(str, extra))} "
                f"(exactly one operator allowed per condition)"
            )
        operator = condition.get("operator")
        if not isinstance(operator, str) or operator not in SUPPORTED_OPERATORS:
            raise ValueError(f'{prefix}: unsupported operator "{operator}"')
        value = condition.get("value")
        if value is None:
            raise ValueError(f'{prefix}: operator "{operator}" requires a value')
        if operator != "equals" and (not isinstance(value, list) or not value):
            raise ValueError(f'{prefix}: operator "{operator}" requires a non-empty list value')


def load_rule(path: str) -> DetectionRule:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Rule file {path} must contain a dictionary")

    required_fields = ["rule_id", "title", "severity", "source", "event_type", "conditions"]
    for field in required_fields:
        if field not in data:
            raise ValueError(f"Rule missing required field: {field}")

    if not isinstance(data["conditions"], list):
        raise ValueError("Rule 'conditions' must be a list")

    if not isinstance(data["rule_id"], str) or not data["rule_id"].strip():
        raise ValueError(f"Rule 'rule_id' must be a non-empty string, got {data['rule_id']!r}")

    validate_conditions(data["rule_id"], data["conditions"])

    return DetectionRule(
        rule_id=data["rule_id"],
        title=data["title"],
        severity=data["severity"],
        source=data["source"],
        event_type=data["event_type"],
        conditions=data["conditions"],
        description=data.get("description"),
        mitre_attack=data.get("mitre_attack"),
    )


RULE_SUFFIXES = (".yaml", ".yml")


def _discover_rule_files(root: Path) -> List[Path]:
    """Rule files under root, sorted by relative POSIX path (never by fs order)."""
    files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in RULE_SUFFIXES]
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def load_rules(rule_root: Union[str, Path]) -> List[DetectionRule]:
    """Load every *.yaml / *.yml rule under rule_root, recursively.

    Fail-fast: an unreadable or invalid rule file, or a duplicate rule ID
    (compared case-insensitively), raises ValueError naming the file(s).
    Nothing is skipped silently. A missing or non-directory root also raises,
    so a mistyped path cannot look like "no detections". Empty or blank YAML
    files are errors too: a rule file must contain a rule.
    """
    root = Path(rule_root)
    if not root.is_dir():
        raise ValueError(f"Rule root is not a directory: {root}")

    rules: List[DetectionRule] = []
    seen: Dict[str, Path] = {}
    for path in _discover_rule_files(root):
        try:
            rule = load_rule(str(path))
        except (ValueError, yaml.YAMLError) as exc:
            raise ValueError(f"Failed to load rule file {path}: {exc}") from exc
        key = rule.rule_id.casefold()
        if key in seen:
            raise ValueError(
                f"Duplicate rule_id {rule.rule_id!r}: defined in {seen[key]} and again in {path}"
            )
        seen[key] = path
        rules.append(rule)
    return rules
