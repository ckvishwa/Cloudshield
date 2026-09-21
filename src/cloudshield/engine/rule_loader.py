import yaml
from typing import Any, List
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

    validate_conditions(str(data["rule_id"]), data["conditions"])

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
