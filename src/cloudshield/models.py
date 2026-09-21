from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class NormalizedEvent:
    source: str
    event_type: str
    timestamp: str
    principal: str
    resource: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DetectionRule:
    rule_id: str
    title: str
    severity: str
    source: str
    event_type: str
    conditions: List[Dict[str, Any]]
    description: Optional[str] = None
    mitre_attack: Optional[str] = None

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    principal: str
    resource: str
    mitre_attack: Optional[str]
    evidence: Dict[str, Any]
