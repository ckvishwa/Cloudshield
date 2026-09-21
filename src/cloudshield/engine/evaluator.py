from typing import Any, Dict, List, Optional
from cloudshield.models import DetectionRule, NormalizedEvent, Finding

def _resolve_field(event: NormalizedEvent, field_path: str) -> Any:
    """Helper to resolve nested fields like 'attributes.roles_added'."""
    parts = field_path.split('.')
    current: Any = event
    for part in parts:
        if isinstance(current, NormalizedEvent):
            if not hasattr(current, part):
                return None
            current = getattr(current, part)
        elif isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        else:
            return None
    return current

SUPPORTED_OPERATORS = ("equals", "contains_any", "contains_all")


def _match_condition(operator: str, actual_val: Any, value: Any) -> Optional[List[Any]]:
    """Return the event values that satisfied the condition, or None if it failed."""
    if operator == "equals":
        return [actual_val] if actual_val == value else None
    if operator not in ("contains_any", "contains_all"):
        raise ValueError(f"Unknown operator: {operator}")
    if not isinstance(value, list):
        raise ValueError(f"'{operator}' requires a list value in the rule condition")
    if not isinstance(actual_val, list):
        return None
    matched = [v for v in dict.fromkeys(actual_val) if v in value]
    if operator == "contains_any":
        return matched or None
    return matched if all(v in actual_val for v in value) else None


def _matched_bindings(event: NormalizedEvent, matched_values: Dict[str, List[Any]]) -> List[Dict[str, Any]]:
    """Bindings (role + member) behind matched roles, so each role keeps its own member."""
    roles = set(matched_values.get("attributes.roles_added", []))
    bindings = event.attributes.get("bindings_added")
    if not roles or not isinstance(bindings, list):
        return []
    return [b for b in bindings if isinstance(b, dict) and b.get("role") in roles]


def evaluate_rule(rule: DetectionRule, event: NormalizedEvent) -> Optional[Finding]:
    if rule.source != event.source:
        return None
    if rule.event_type != event.event_type:
        return None

    matched_values: Dict[str, List[Any]] = {}
    for condition in rule.conditions:
        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")

        if not field or not operator or value is None:
            raise ValueError("Condition must specify 'field', 'operator', and 'value'")

        matched = _match_condition(operator, _resolve_field(event, field), value)
        if matched is None:
            return None
        matched_values[field] = matched

    evidence: Dict[str, Any] = {
        "event_attributes": event.attributes,
        "matched_conditions": rule.conditions,
    }
    bindings = _matched_bindings(event, matched_values)
    if bindings:
        evidence["matched_bindings"] = bindings

    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        principal=event.principal,
        resource=event.resource,
        mitre_attack=rule.mitre_attack,
        evidence=evidence,
        timestamp=event.timestamp,
        method_name=event.attributes.get("method_name"),
        source_ip=event.attributes.get("source_ip"),
        matched_values=matched_values,
    )
