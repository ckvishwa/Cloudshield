import yaml
from typing import Any, Dict
from cloudshield.models import DetectionRule

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
