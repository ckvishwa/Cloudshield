from typing import Any, Dict, List
from cloudshield.models import NormalizedEvent

def normalize_gcp_audit_event(raw: Dict[str, Any]) -> NormalizedEvent:
    proto_payload = raw.get("protoPayload", {})
    if not isinstance(proto_payload, dict):
        proto_payload = {}
        
    auth_info = proto_payload.get("authenticationInfo", {})
    if not isinstance(auth_info, dict):
        auth_info = {}
        
    principal = auth_info.get("principalEmail", "unknown")
    resource = proto_payload.get("resourceName", "unknown")
    timestamp = raw.get("timestamp", "unknown")

    event_type = "gcp.audit.generic"
    attributes: Dict[str, Any] = {}

    binding_deltas: List[Any] = []
    
    metadata = proto_payload.get("metadata", {})
    if isinstance(metadata, dict):
        deltas = metadata.get("bindingDeltas")
        if isinstance(deltas, list):
            binding_deltas.extend(deltas)
            
    service_data = proto_payload.get("serviceData", {})
    if isinstance(service_data, dict):
        policy_delta = service_data.get("policyDelta", {})
        if isinstance(policy_delta, dict):
            deltas = policy_delta.get("bindingDeltas")
            if isinstance(deltas, list):
                binding_deltas.extend(deltas)

    if binding_deltas:
        event_type = "gcp.iam.policy_change"
        roles_added = []
        roles_removed = []
        for delta in binding_deltas:
            if not isinstance(delta, dict):
                continue
            action = delta.get("action")
            role = delta.get("role")
            if isinstance(role, str) and role:
                if action == "ADD":
                    roles_added.append(role)
                elif action == "REMOVE":
                    roles_removed.append(role)
        attributes["roles_added"] = roles_added
        attributes["roles_removed"] = roles_removed

    return NormalizedEvent(
        source="gcp_audit",
        event_type=event_type,
        timestamp=timestamp,
        principal=principal,
        resource=resource,
        attributes=attributes,
        raw=raw
    )
