from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class NormalizedEvent:
    source: str
    event_type: str
    timestamp: Optional[str]
    principal: Optional[str]
    resource: Optional[str]
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
    principal: Optional[str]
    resource: Optional[str]
    mitre_attack: Optional[str]
    evidence: Dict[str, Any]
    timestamp: Optional[str] = None
    method_name: Optional[str] = None
    source_ip: Optional[str] = None
    # condition field -> event values that satisfied the condition
    matched_values: Dict[str, List[Any]] = field(default_factory=dict)
