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

def evaluate_rule(rule: DetectionRule, event: NormalizedEvent) -> Optional[Finding]:
    if rule.source != event.source:
        return None
    if rule.event_type != event.event_type:
        return None

    for condition in rule.conditions:
        field = condition.get("field")
        operator = condition.get("operator")
        value = condition.get("value")

        if not field or not operator or value is None:
            raise ValueError("Condition must specify 'field', 'operator', and 'value'")

        actual_val = _resolve_field(event, field)
        
        if operator == "equals":
            if actual_val != value:
                return None
        elif operator == "contains_any":
            if not isinstance(actual_val, list):
                return None
            if not isinstance(value, list):
                raise ValueError("'contains_any' requires a list value in the rule condition")
            if not any(v in actual_val for v in value):
                return None
        elif operator == "contains_all":
            if not isinstance(actual_val, list):
                return None
            if not isinstance(value, list):
                raise ValueError("'contains_all' requires a list value in the rule condition")
            if not all(v in actual_val for v in value):
                return None
        else:
            raise ValueError(f"Unknown operator: {operator}")

    # If all conditions pass, create finding
    evidence = {
        "event_attributes": event.attributes,
        "matched_conditions": rule.conditions
    }

    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        principal=event.principal,
        resource=event.resource,
        mitre_attack=rule.mitre_attack,
        evidence=evidence
    )
