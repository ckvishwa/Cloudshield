from typing import Any, Dict, List, Optional
from cloudshield.models import NormalizedEvent


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _collect_binding_deltas(proto_payload: Dict[str, Any]) -> List[Any]:
    deltas: List[Any] = []
    metadata = _as_dict(proto_payload.get("metadata"))
    policy_delta = _as_dict(_as_dict(proto_payload.get("serviceData")).get("policyDelta"))
    for candidate in (metadata.get("bindingDeltas"), policy_delta.get("bindingDeltas")):
        if isinstance(candidate, list):
            deltas.extend(candidate)
    return deltas


def normalize_gcp_audit_event(raw: Dict[str, Any]) -> NormalizedEvent:
    """Normalize a raw GCP audit log entry.

    Absent optional values are None, never fabricated placeholders.
    """
    proto_payload = _as_dict(raw.get("protoPayload"))
    auth_info = _as_dict(proto_payload.get("authenticationInfo"))
    request_metadata = _as_dict(proto_payload.get("requestMetadata"))

    attributes: Dict[str, Any] = {
        "method_name": _as_str(proto_payload.get("methodName")),
        "source_ip": _as_str(request_metadata.get("callerIp")),
    }
    event_type = "gcp.audit.generic"

    binding_deltas = _collect_binding_deltas(proto_payload)
    if binding_deltas:
        event_type = "gcp.iam.policy_change"
        roles_added: List[str] = []
        roles_removed: List[str] = []
        bindings_added: List[Dict[str, Optional[str]]] = []
        for delta in binding_deltas:
            if not isinstance(delta, dict):
                continue
            action = delta.get("action")
            role = _as_str(delta.get("role"))
            if role is None:
                continue
            if action == "ADD":
                roles_added.append(role)
                bindings_added.append({"role": role, "member": _as_str(delta.get("member"))})
            elif action == "REMOVE":
                roles_removed.append(role)
        attributes["roles_added"] = roles_added
        attributes["roles_removed"] = roles_removed
        attributes["bindings_added"] = bindings_added

    return NormalizedEvent(
        source="gcp_audit",
        event_type=event_type,
        timestamp=_as_str(raw.get("timestamp")),
        principal=_as_str(auth_info.get("principalEmail")),
        resource=_as_str(proto_payload.get("resourceName")),
        attributes=attributes,
        raw=raw,
    )
