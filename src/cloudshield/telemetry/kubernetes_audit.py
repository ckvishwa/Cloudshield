"""Normalize Kubernetes / GKE audit telemetry into NormalizedEvent.

Two input shapes are supported, chosen by explicit shape checks:

* native: a Kubernetes ``audit.k8s.io`` ``Event`` (apiVersion ``audit.k8s.io/*``
  and kind ``Event``).
* gke: a GKE Cloud Audit Log entry (``protoPayload.serviceName == "k8s.io"`` and
  ``resource.type == "k8s_cluster"``).

Anything else normalizes to a generic event with ``format = None``; an arbitrary
GCP audit entry never becomes a Kubernetes event.

Documented assumptions (kept deliberately small):

* Native ``requestObject`` and GKE ``protoPayload.request`` are the Kubernetes
  object (or patch document) itself. GKE's own documentation queries
  ``protoPayload.request.metadata.name``, which supports this for GKE.
* GKE method names look like ``io.k8s.core.v1.pods.create`` /
  ``io.k8s.authorization.rbac.v1.clusterrolebindings.create``; the API group is
  taken from ``resourceName`` when present, else from a small table of groups
  (core, apps, batch, rbac). Unknown groups stay ``None``.
* Native events are actionable only at stage ``ResponseComplete`` (one API request
  emits several stages; the others would duplicate it). GKE entries have no stage.
* Outcome: a native ``responseStatus.code`` in 200-299 is success, anything else is
  failure. For GKE, ``protoPayload.status.code`` is a gRPC code (0 = OK). If the log
  has no status the outcome is unknown (``operation_succeeded = None``) and is not
  treated as a failure or as a confirmed success. HTTP 101 (Switching Protocols,
  the normal result of a pods/exec upgrade) also counts as success.
* Response bodies are never read and Secret objects are never copied.
* The raw event is input only. The returned NormalizedEvent never retains it
  (``raw`` is always ``{}``): request and response bodies can carry Secret data,
  tokens or other user-supplied content, and the detection engine only needs the
  minimal facts extracted into ``attributes``.
"""
import re
from typing import Any, Dict, List, Optional

from cloudshield.models import NormalizedEvent

SOURCE = "kubernetes_audit"
EVENT_WORKLOAD_CHANGE = "k8s.workload.change"
EVENT_RBAC_BINDING_CHANGE = "k8s.rbac.binding_change"
EVENT_POD_EXEC = "k8s.pod.exec"
EVENT_SECRET_ACCESS = "k8s.secret.access"
EVENT_GENERIC = "k8s.audit.generic"

FORMAT_NATIVE = "native"
FORMAT_GKE = "gke"

WRITE_VERBS = ("create", "update", "patch")
KNOWN_VERBS = frozenset({
    "get", "list", "watch", "create", "update", "patch", "delete", "deletecollection",
    "connect", "proxy", "redirect",
})
EXEC_VERBS = ("create", "get", "connect")  # pods/exec is POST (create) or a GET upgrade
SECRET_ACCESS_TYPES = {"get": "read", "list": "enumeration", "watch": "watch"}
# Explicit allowlist of capabilities treated as dangerous (upper-case, no CAP_ prefix).
DANGEROUS_CAPABILITIES = ("SYS_ADMIN", "SYS_PTRACE")
ACTIONABLE_NATIVE_STAGE = "ResponseComplete"
RBAC_API_GROUP = "rbac.authorization.k8s.io"

_GKE_METHOD_PREFIX = "io.k8s."
_GKE_VERSION_RE = re.compile(r"^v\d+((alpha|beta)\d+)?$")
_GKE_GROUPS = {"core": "", "apps": "apps", "batch": "batch", "authorization.rbac": RBAC_API_GROUP}
_POD_CONTAINER_LISTS = ("containers", "initContainers", "ephemeralContainers")
_SUBJECT_FIELDS = ("kind", "name", "namespace", "apiGroup")


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _lower(value: Optional[str]) -> Optional[str]:
    return value.lower() if value else None


def _http_success(code: Optional[int]) -> Optional[bool]:
    """2xx and 101 (Switching Protocols, used by exec) are success; unknown stays None."""
    if code is None:
        return None
    return 200 <= code < 300 or code == 101


def _str_list(value: Any) -> List[str]:
    return [v for v in value if isinstance(v, str) and v] if isinstance(value, list) else []


def _http_code(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def detect_format(raw: Any) -> Optional[str]:
    """'native', 'gke' or None, from explicit shape checks."""
    if not isinstance(raw, dict):
        return None
    api_version = raw.get("apiVersion")
    if isinstance(api_version, str) and api_version.startswith("audit.k8s.io/") and raw.get("kind") == "Event":
        return FORMAT_NATIVE
    if _dict(raw.get("protoPayload")).get("serviceName") == "k8s.io" \
            and _dict(raw.get("resource")).get("type") == "k8s_cluster":
        return FORMAT_GKE
    return None


def kubernetes_raw_timestamp(raw: Any) -> Any:
    """The raw timestamp value used for replay pacing and validation."""
    detected = detect_format(raw)
    if detected == FORMAT_NATIVE:
        return raw.get("stageTimestamp") or raw.get("requestReceivedTimestamp")
    if isinstance(raw, dict):
        return raw.get("timestamp")
    return None


def _empty_attributes() -> Dict[str, Any]:
    return {
        "format": None, "audit_id": None, "stage": None, "verb": None,
        "username": None, "groups": [], "impersonated_username": None,
        "source_ips": [], "user_agent": None,
        "api_group": None, "api_version": None, "resource": None, "subresource": None,
        "namespace": None, "name": None,
        "status_code": None, "rpc_status_code": None, "operation_succeeded": None,
        "actionable_stage": False,
        "cluster_name": None, "cluster_location": None, "project_id": None,
        "request_body_available": False, "request_object": None,
        "has_privileged_container": None, "privileged_containers": [], "privileged_container_count": None,
        "rbac_role_ref_kind": None, "rbac_role_ref_name": None, "rbac_subjects": [],
        "is_exec": False,
        "secret_access_type": None, "secret_name": None,
        "host_network": None, "host_pid": None, "host_ipc": None,
        "host_path_volumes": [], "dangerous_capabilities": [], "dangerous_capability_containers": [],
        "has_dangerous_host_config": None,
    }


def _native_fields(raw: Dict[str, Any]) -> Dict[str, Any]:
    object_ref = _dict(raw.get("objectRef"))
    user = _dict(raw.get("user"))
    has_ref = bool(object_ref)
    status_code = _http_code(_dict(raw.get("responseStatus")).get("code"))
    return {
        "format": FORMAT_NATIVE,
        "audit_id": _str(raw.get("auditID")),
        "stage": _str(raw.get("stage")),
        "verb": _str(raw.get("verb")),
        "username": _str(user.get("username")),
        "groups": _str_list(user.get("groups")),
        "impersonated_username": _str(_dict(raw.get("impersonatedUser")).get("username")),
        "source_ips": _str_list(raw.get("sourceIPs")),
        "user_agent": _str(raw.get("userAgent")),
        "api_group": (object_ref["apiGroup"] if isinstance(object_ref.get("apiGroup"), str) else "") if has_ref else None,
        "api_version": _str(object_ref.get("apiVersion")),
        "resource": _lower(_str(object_ref.get("resource"))),
        "subresource": _lower(_str(object_ref.get("subresource"))),
        "namespace": _str(object_ref.get("namespace")),
        "name": _str(object_ref.get("name")),
        "status_code": status_code,
        "operation_succeeded": _http_success(status_code),
        "actionable_stage": raw.get("stage") == ACTIONABLE_NATIVE_STAGE,
        "request": raw.get("requestObject"),
        "principal": _str(user.get("username")),
        "timestamp": _str(raw.get("stageTimestamp")) or _str(raw.get("requestReceivedTimestamp")),
    }


def _parse_gke_method(method_name: Optional[str]) -> Dict[str, Optional[str]]:
    """verb / group / version / resource / subresource from e.g. io.k8s.core.v1.pods.exec.create."""
    parsed: Dict[str, Optional[str]] = {"verb": None, "api_group": None, "api_version": None,
                                        "resource": None, "subresource": None}
    method_name = method_name.lower() if method_name else None
    if not method_name or not method_name.startswith(_GKE_METHOD_PREFIX):
        return parsed
    tokens = method_name[len(_GKE_METHOD_PREFIX):].split(".")
    if len(tokens) < 3:
        return parsed
    verb = tokens[-1].lower()
    parsed["verb"] = verb if verb in KNOWN_VERBS else None
    version_index = next((i for i, t in enumerate(tokens[:-1]) if _GKE_VERSION_RE.match(t)), None)
    if version_index is None or version_index == 0:
        return parsed
    parsed["api_group"] = _GKE_GROUPS.get(".".join(tokens[:version_index]))
    parsed["api_version"] = tokens[version_index]
    rest = tokens[version_index + 1:-1]
    parsed["resource"] = rest[0] if rest else None
    parsed["subresource"] = rest[1] if len(rest) > 1 else None
    return parsed


def _parse_gke_resource_name(resource_name: Optional[str]) -> Dict[str, Optional[str]]:
    """group / version / namespace / resource / name from core/v1/namespaces/ns/pods/name."""
    parsed: Dict[str, Optional[str]] = {"api_group": None, "api_version": None, "namespace": None,
                                        "resource": None, "name": None}
    if not resource_name:
        return parsed
    segments = resource_name.strip("/").split("/")
    if len(segments) < 3 or not _GKE_VERSION_RE.match(segments[1]):
        return parsed
    parsed["api_group"] = "" if segments[0] == "core" else segments[0]
    parsed["api_version"] = segments[1]
    rest = segments[2:]
    if rest[0] == "namespaces" and len(rest) >= 3:
        parsed["namespace"] = rest[1]
        rest = rest[2:]
    parsed["resource"] = rest[0].lower()
    parsed["name"] = rest[1] if len(rest) > 1 else None
    return parsed


def _gke_fields(raw: Dict[str, Any]) -> Dict[str, Any]:
    proto = _dict(raw.get("protoPayload"))
    labels = _dict(_dict(raw.get("resource")).get("labels"))
    auth = _dict(proto.get("authenticationInfo"))
    metadata = _dict(proto.get("requestMetadata"))
    from_method = _parse_gke_method(_str(proto.get("methodName")))
    from_name = _parse_gke_resource_name(_str(proto.get("resourceName")))
    consistent = from_name["resource"] is not None and from_name["resource"] == from_method["resource"]
    rpc_code = _http_code(_dict(proto.get("status")).get("code"))
    caller_ip = _str(metadata.get("callerIp"))
    return {
        "format": FORMAT_GKE,
        "verb": from_method["verb"],
        "username": _str(auth.get("principalEmail")),
        "source_ips": [caller_ip] if caller_ip else [],
        "user_agent": _str(metadata.get("callerSuppliedUserAgent")),
        "api_group": from_name["api_group"] if consistent and from_name["api_group"] is not None
        else from_method["api_group"],
        "api_version": from_method["api_version"] or (from_name["api_version"] if consistent else None),
        "resource": from_method["resource"],
        "subresource": from_method["subresource"],
        "namespace": from_name["namespace"] if consistent else None,
        "name": from_name["name"] if consistent else None,
        "rpc_status_code": rpc_code,
        "operation_succeeded": None if rpc_code is None else rpc_code == 0,
        "actionable_stage": True,
        "cluster_name": _str(labels.get("cluster_name")),
        "cluster_location": _str(labels.get("location")),
        "project_id": _str(labels.get("project_id")),
        "request": proto.get("request"),
        "principal": _str(auth.get("principalEmail")),
        "timestamp": _str(raw.get("timestamp")),
    }


def _capability_names(security_context: Dict[str, Any]) -> List[str]:
    """Upper-cased capabilities.add entries (CAP_ prefix stripped); non-strings are skipped."""
    capabilities = _dict(security_context.get("capabilities")).get("add")
    if not isinstance(capabilities, list):
        return []
    names = []
    for capability in capabilities:
        if isinstance(capability, str) and capability.strip():
            name = capability.strip().upper()
            names.append(name[4:] if name.startswith("CAP_") else name)
    return names


def _host_path_volumes(spec: Dict[str, Any], mounts: Dict[str, List[bool]]) -> List[Dict[str, Any]]:
    """hostPath volumes as {name, path, read_only}.

    read_only is derived from the volumeMounts that use the volume: True if every
    mount is readOnly, False if any is not, None if the volume is not mounted.
    """
    volumes = spec.get("volumes")
    found: List[Dict[str, Any]] = []
    if not isinstance(volumes, list):
        return found
    for volume in volumes:
        if not isinstance(volume, dict) or not isinstance(volume.get("hostPath"), dict):
            continue
        name = _str(volume.get("name"))
        flags = mounts.get(name, []) if name else []
        found.append({"name": name, "path": _str(volume["hostPath"].get("path")),
                      "read_only": None if not flags else all(flags)})
    return found


def _inspect_pod_body(body: Any) -> Optional[Dict[str, Any]]:
    """Explicit allowlist of pod-spec security facts, or None if the body cannot be inspected.

    Only booleans that are exactly True count ("true" and 1 do not). Containers,
    initContainers and ephemeralContainers are all inspected. ``unreadable`` is
    True when a container list was malformed, so "nothing found" is not conclusive.
    allowPrivilegeEscalation is not privileged and is not reported.
    """
    if not isinstance(body, dict):
        return None
    spec = body.get("spec")
    if spec is None:
        spec = {}
    if not isinstance(spec, dict):
        return None
    privileged: List[str] = []
    dangerous_caps: List[str] = []
    cap_containers: List[str] = []
    mounts: Dict[str, List[bool]] = {}
    unreadable = False
    for key in _POD_CONTAINER_LISTS:
        containers = spec.get(key)
        if containers is None:
            continue
        if not isinstance(containers, list):
            unreadable = True
            continue
        for index, container in enumerate(containers):
            if not isinstance(container, dict):
                unreadable = True
                continue
            label = _str(container.get("name")) or f"{key}[{index}]"
            security_context = _dict(container.get("securityContext"))
            if security_context.get("privileged") is True:
                privileged.append(label)
            found = [c for c in _capability_names(security_context) if c in DANGEROUS_CAPABILITIES]
            if found:
                cap_containers.append(label)
                dangerous_caps.extend(c for c in found if c not in dangerous_caps)
            volume_mounts = container.get("volumeMounts")
            for mount in volume_mounts if isinstance(volume_mounts, list) else []:
                if isinstance(mount, dict) and _str(mount.get("name")):
                    mounts.setdefault(mount["name"], []).append(mount.get("readOnly") is True)
    return {
        "privileged": privileged,
        "unreadable": unreadable,
        "host_network": spec.get("hostNetwork") is True,
        "host_pid": spec.get("hostPID") is True,
        "host_ipc": spec.get("hostIPC") is True,
        "host_path_volumes": _host_path_volumes(spec, mounts),
        "dangerous_capabilities": dangerous_caps,
        "dangerous_capability_containers": cap_containers,
    }


def _pod_facts(body: Any) -> Dict[str, Any]:
    """Attributes for a pod write: privileged containers and dangerous host-level configuration.

    Tri-state (True / False / None): None means the request body was unavailable or
    malformed and nothing dangerous was found, so "not dangerous" is not concluded.
    """
    facts = _inspect_pod_body(body)
    if facts is None:
        return {"has_privileged_container": None, "privileged_containers": [], "privileged_container_count": None,
                "has_dangerous_host_config": None}
    privileged = facts["privileged"]
    dangerous = bool(facts["host_network"] or facts["host_pid"] or facts["host_ipc"]
                     or facts["host_path_volumes"] or facts["dangerous_capabilities"])
    return {
        "has_privileged_container": True if privileged else (None if facts["unreadable"] else False),
        "privileged_containers": privileged,
        "privileged_container_count": len(privileged) if privileged or not facts["unreadable"] else None,
        "host_network": facts["host_network"], "host_pid": facts["host_pid"], "host_ipc": facts["host_ipc"],
        "host_path_volumes": facts["host_path_volumes"],
        "dangerous_capabilities": facts["dangerous_capabilities"],
        "dangerous_capability_containers": facts["dangerous_capability_containers"],
        "has_dangerous_host_config": True if dangerous else (None if facts["unreadable"] else False),
    }


def _rbac_binding_facts(body: Any) -> Dict[str, Any]:
    role_ref = _dict(_dict(body).get("roleRef"))
    subjects_raw = _dict(body).get("subjects")
    subjects: List[Dict[str, str]] = []
    if isinstance(subjects_raw, list):
        for subject in subjects_raw:
            if isinstance(subject, dict):
                kept = {k: subject[k] for k in _SUBJECT_FIELDS if _str(subject.get(k))}
                if kept:
                    subjects.append(kept)
    return {"rbac_role_ref_kind": _str(role_ref.get("kind")), "rbac_role_ref_name": _str(role_ref.get("name")),
            "rbac_subjects": subjects}


def _compact_request_object(body: Any) -> Optional[Dict[str, Optional[str]]]:
    """Identity of the request object only; the spec and any data are never copied."""
    if not isinstance(body, dict):
        return None
    metadata = _dict(body.get("metadata"))
    return {"kind": _str(body.get("kind")), "apiVersion": _str(body.get("apiVersion")),
            "name": _str(metadata.get("name")), "namespace": _str(metadata.get("namespace"))}


def _event_type(attributes: Dict[str, Any]) -> str:
    """Route to a specific event type only for successful/unknown-outcome requests at an actionable stage.

    A failed request (non-success status) or a non-actionable audit stage is generic.
    """
    if not attributes["actionable_stage"] or attributes["operation_succeeded"] is False:
        return EVENT_GENERIC
    verb, resource, subresource, group = (attributes[k] for k in ("verb", "resource", "subresource", "api_group"))
    if group == "":
        if resource == "pods" and subresource == "exec" and verb in EXEC_VERBS:
            return EVENT_POD_EXEC
        if resource == "secrets" and not subresource and verb in SECRET_ACCESS_TYPES:
            return EVENT_SECRET_ACCESS
        if resource == "pods" and not subresource and verb in WRITE_VERBS:
            return EVENT_WORKLOAD_CHANGE
    elif group == RBAC_API_GROUP and resource == "clusterrolebindings" and not subresource and verb in WRITE_VERBS:
        return EVENT_RBAC_BINDING_CHANGE
    return EVENT_GENERIC


def _resource_path(attributes: Dict[str, Any]) -> Optional[str]:
    if not attributes["resource"]:
        return None
    parts = (["namespaces", attributes["namespace"]] if attributes["namespace"] else []) + [attributes["resource"]]
    if attributes["name"]:
        parts.append(attributes["name"])
    return "/".join(parts)


def normalize_kubernetes_audit_event(raw: Any) -> NormalizedEvent:
    """Normalize a native Kubernetes audit Event or a GKE Cloud Audit Log wrapper."""
    detected = detect_format(raw)
    attributes = _empty_attributes()
    if detected is None:
        return NormalizedEvent(source=SOURCE, event_type=EVENT_GENERIC, timestamp=None, principal=None,
                               resource=None, attributes=attributes, raw={})

    fields = _native_fields(raw) if detected == FORMAT_NATIVE else _gke_fields(raw)
    body = fields.pop("request")
    principal = fields.pop("principal")
    timestamp = fields.pop("timestamp")
    fields["verb"] = fields["verb"].lower() if fields.get("verb") else None
    if fields["verb"] not in KNOWN_VERBS:
        fields["verb"] = None
    attributes.update(fields)

    if attributes["name"] is None and isinstance(body, dict):
        attributes["name"] = _str(_dict(body.get("metadata")).get("name"))
    attributes["request_body_available"] = isinstance(body, (dict, list))
    is_secret = attributes["resource"] == "secrets"
    attributes["request_object"] = None if is_secret else _compact_request_object(body)

    core = attributes["api_group"] == ""
    if core and attributes["resource"] == "pods" and attributes["subresource"] == "exec" \
            and attributes["verb"] in EXEC_VERBS:
        attributes["is_exec"] = True
    if core and is_secret and not attributes["subresource"] and attributes["verb"] in SECRET_ACCESS_TYPES:
        attributes["secret_access_type"] = SECRET_ACCESS_TYPES[attributes["verb"]]
        attributes["secret_name"] = attributes["name"]
    if attributes["verb"] in WRITE_VERBS and not attributes["subresource"]:
        if attributes["resource"] == "pods" and core:
            attributes.update(_pod_facts(body))
        elif attributes["resource"] == "clusterrolebindings" and attributes["api_group"] == RBAC_API_GROUP:
            attributes.update(_rbac_binding_facts(body))

    return NormalizedEvent(
        source=SOURCE,
        event_type=_event_type(attributes),
        timestamp=timestamp,
        principal=principal,
        resource=_resource_path(attributes),
        attributes=attributes,
        raw={},
    )
