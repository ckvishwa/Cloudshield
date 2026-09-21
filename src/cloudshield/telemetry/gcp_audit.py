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


IAM_CREDENTIALS_SERVICE = "iamcredentials.googleapis.com"
CREDENTIAL_TYPES = {
    "GenerateAccessToken": "access_token",
    "GenerateIdToken": "id_token",
    "SignJwt": "signed_jwt",
    "SignBlob": "signed_blob",
}
SERVICE_ACCOUNT_DOMAIN = "gserviceaccount.com"
SERVICE_ACCOUNT_PATH_MARKER = "/serviceAccounts/"


def _short_method(method_name: Optional[str]) -> Optional[str]:
    """'google.iam.credentials.v1.IAMCredentials.SignJwt' -> 'SignJwt'."""
    return method_name.rsplit(".", 1)[-1] if method_name else None


def _service_account_email(value: Any) -> Optional[str]:
    """Return a lowercase service-account email from a bare email or a
    'projects/<p>/serviceAccounts/<email>' resource name, else None."""
    text = _as_str(value)
    if text is None:
        return None
    if SERVICE_ACCOUNT_PATH_MARKER in text:
        text = text.rsplit(SERVICE_ACCOUNT_PATH_MARKER, 1)[-1]
    text = text.strip().lower()
    local, sep, domain = text.partition("@")
    if not sep or not local or "/" in text or "@" in domain:
        return None
    if domain != SERVICE_ACCOUNT_DOMAIN and not domain.endswith("." + SERVICE_ACCOUNT_DOMAIN):
        return None
    return text


def _target_service_account(raw: Dict[str, Any], proto_payload: Dict[str, Any]) -> Optional[str]:
    labels = _as_dict(_as_dict(raw.get("resource")).get("labels"))
    candidates = (
        labels.get("email_id"),
        _as_dict(proto_payload.get("request")).get("name"),
        proto_payload.get("resourceName"),
    )
    for candidate in candidates:
        email = _service_account_email(candidate)
        if email:
            return email
    return None


def _delegation_chain(auth_info: Dict[str, Any]) -> List[str]:
    """Compact list of delegating principals; malformed entries are skipped."""
    entries = auth_info.get("serviceAccountDelegationInfo")
    if not isinstance(entries, list):
        return []
    chain: List[str] = []
    for entry in entries:
        entry = _as_dict(entry)
        identity = _as_str(entry.get("principalSubject")) or _as_str(
            _as_dict(entry.get("firstPartyPrincipal")).get("principalEmail")
        )
        if identity:
            chain.append(identity)
    return chain


def _is_set_iam_policy(method_name: Optional[str]) -> bool:
    """True when the final dot-separated component is exactly SetIamPolicy.

    Case-insensitive so 'SetIAMPolicy' (IAM admin API) matches, but exact on the
    final component, so 'NotSetIamPolicy' or 'SetIamPolicyPreview' do not.
    """
    if not method_name:
        return False
    return method_name.rsplit(".", 1)[-1].casefold() == "setiampolicy"


def _parse_binding_deltas(binding_deltas: List[Any]) -> Dict[str, Any]:
    """Roles proven added/removed by well-formed ADD/REMOVE binding deltas."""
    roles_added: List[str] = []
    roles_removed: List[str] = []
    bindings_added: List[Dict[str, Optional[str]]] = []
    usable = 0
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
            usable += 1
        elif action == "REMOVE":
            roles_removed.append(role)
            usable += 1
    return {
        "roles_added": roles_added,
        "roles_removed": roles_removed,
        "bindings_added": bindings_added,
        "policy_delta_present": usable > 0,
    }


def _extract_bindings(candidate: Any) -> Optional[List[Dict[str, Any]]]:
    """Compact {role, members} list from a policy 'bindings' value.

    None when candidate is not a list (source unusable). Malformed bindings are
    skipped: role must be a non-empty string and members a list holding at
    least one string (non-string members are dropped).
    """
    if not isinstance(candidate, list):
        return None
    bindings: List[Dict[str, Any]] = []
    for binding in candidate:
        if not isinstance(binding, dict):
            continue
        role = _as_str(binding.get("role"))
        members = binding.get("members")
        if role is None or not isinstance(members, list):
            continue
        member_strings = [m for m in members if isinstance(m, str) and m]
        if member_strings:
            bindings.append({"role": role, "members": member_strings})
    return bindings


def _policy_snapshot(proto_payload: Dict[str, Any]) -> Dict[str, Any]:
    """Resulting policy of a SetIamPolicy call: response.bindings, else request.policy.bindings.

    Exactly one source is used (never merged). The response is preferred because
    it is the policy as returned after the operation.
    """
    source: Optional[str] = None
    bindings = _extract_bindings(_as_dict(proto_payload.get("response")).get("bindings"))
    if bindings is not None:
        source = "response"
    else:
        policy = _as_dict(_as_dict(proto_payload.get("request")).get("policy"))
        bindings = _extract_bindings(policy.get("bindings"))
        if bindings is not None:
            source = "request"
    bindings = bindings or []
    return {
        "policy_snapshot_source": source,
        "roles_present_after": list(dict.fromkeys(b["role"] for b in bindings)),
        "bindings_present_after": bindings,
    }


def _policy_change_attributes(proto_payload: Dict[str, Any], binding_deltas: List[Any]) -> Dict[str, Any]:
    """Attributes for gcp.iam.policy_change.

    roles_added / roles_removed come ONLY from binding deltas (proven changes).
    roles_present_after comes from a policy snapshot and never implies a grant.
    """
    attributes = _parse_binding_deltas(binding_deltas)
    attributes.update(_policy_snapshot(proto_payload))
    return attributes


def _credential_generation_attributes(
    raw: Dict[str, Any], proto_payload: Dict[str, Any], auth_info: Dict[str, Any],
    principal: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Attributes for iamcredentials token/sign calls; None for anything else.

    Only the caller, target and call metadata are kept. Request/response
    bodies (tokens, JWTs, signatures) are never copied.
    """
    if proto_payload.get("serviceName") != IAM_CREDENTIALS_SERVICE:
        return None
    method = _short_method(_as_str(proto_payload.get("methodName")))
    if method not in CREDENTIAL_TYPES:
        return None
    target = _target_service_account(raw, proto_payload)
    return {
        "service_name": IAM_CREDENTIALS_SERVICE,
        "credential_type": CREDENTIAL_TYPES[method],
        "target_service_account": target,
        "principal_subject": _as_str(auth_info.get("principalSubject")),
        "delegation_chain": _delegation_chain(auth_info),
        "self_impersonation": principal is not None and principal.lower() == target,
    }


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
    principal = _as_str(auth_info.get("principalEmail"))

    credential_attributes = _credential_generation_attributes(
        raw, proto_payload, auth_info, principal
    )
    if credential_attributes is not None:
        event_type = "gcp.iam.service_account_credential_generation"
        attributes.update(credential_attributes)

    if credential_attributes is None:
        binding_deltas = _collect_binding_deltas(proto_payload)
        if binding_deltas or _is_set_iam_policy(attributes["method_name"]):
            event_type = "gcp.iam.policy_change"
            attributes.update(_policy_change_attributes(proto_payload, binding_deltas))

    return NormalizedEvent(
        source="gcp_audit",
        event_type=event_type,
        timestamp=_as_str(raw.get("timestamp")),
        principal=principal,
        resource=_as_str(proto_payload.get("resourceName")),
        attributes=attributes,
        raw=raw,
    )
