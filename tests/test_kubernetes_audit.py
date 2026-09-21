import copy
import json

import pytest
from k8s_helpers import RBAC, crb, gke, native, pod

from cloudshield.telemetry.kubernetes_audit import (
    detect_format,
    kubernetes_raw_timestamp,
    normalize_kubernetes_audit_event as normalize,
)
from cloudshield.telemetry.registry import ADAPTERS, get_adapter

CRB = dict(resource="clusterrolebindings", namespace=None, name="dev-cluster-admin", api_group=RBAC)


# ---- format detection ------------------------------------------------------------

def test_native_event_is_recognized():
    event = normalize(native(request=pod()))

    assert detect_format(native()) == "native"
    assert event.source == "kubernetes_audit"
    assert event.attributes["format"] == "native"


def test_gke_wrapper_is_recognized():
    assert detect_format(gke()) == "gke"
    assert normalize(gke(request=pod())).attributes["format"] == "gke"


@pytest.mark.parametrize("raw", [
    {"protoPayload": {"serviceName": "iam.googleapis.com", "methodName": "SetIamPolicy"},
     "resource": {"type": "project"}},
    {"protoPayload": {"serviceName": "k8s.io"}, "resource": {"type": "project"}},          # wrong resource type
    {"protoPayload": {"serviceName": "iam.googleapis.com"}, "resource": {"type": "k8s_cluster"}},  # wrong service
    {"apiVersion": "audit.k8s.io/v1", "kind": "Policy"},                                    # not an Event
    {"apiVersion": "v1", "kind": "Event"},                                                  # core Event, not audit
    {"kind": "Event"}, {}, [], "text", 5, None,
])
def test_unrelated_or_malformed_input_is_not_kubernetes_telemetry(raw):
    event = normalize(raw)

    assert detect_format(raw) is None
    assert event.event_type == "k8s.audit.generic"
    assert event.attributes["format"] is None
    assert event.principal is None and event.resource is None


def test_gcp_audit_entry_is_not_turned_into_a_kubernetes_event():
    raw = {"protoPayload": {"serviceName": "iam.googleapis.com", "methodName": "SetIamPolicy",
                            "authenticationInfo": {"principalEmail": "admin@example.com"}},
           "resource": {"type": "project"}}
    event = normalize(raw)

    assert event.attributes["username"] is None and event.attributes["verb"] is None


# ---- common fields -----------------------------------------------------------------

def test_native_principal_groups_and_source_ips():
    event = normalize(native(groups=("system:authenticated", "devs"), ips=("203.0.113.10", "203.0.113.11"),
                             extra={"impersonatedUser": {"username": "system:admin"}}))

    assert event.principal == "developer@example.com"
    assert event.attributes["username"] == "developer@example.com"
    assert event.attributes["groups"] == ["system:authenticated", "devs"]
    assert event.attributes["source_ips"] == ["203.0.113.10", "203.0.113.11"]
    assert event.attributes["impersonated_username"] == "system:admin"
    assert event.attributes["user_agent"] == "kubectl/v1.30.0"
    assert event.attributes["audit_id"] == "00000000-0000-4000-8000-000000000001"


def test_gke_principal_and_caller_ip_are_normalized_into_source_ips():
    event = normalize(gke())

    assert event.principal == "developer@example.com"
    assert event.attributes["source_ips"] == ["203.0.113.10"]
    assert event.attributes["groups"] == []
    assert event.attributes["user_agent"] == "kubectl/v1.30.0"


def test_missing_principal_and_ips_are_none_or_empty_never_fabricated():
    raw = native()
    del raw["user"], raw["sourceIPs"]
    event = normalize(raw)

    assert event.principal is None and event.attributes["username"] is None
    assert event.attributes["source_ips"] == []
    payload = gke()
    del payload["protoPayload"]["authenticationInfo"], payload["protoPayload"]["requestMetadata"]
    assert normalize(payload).principal is None and normalize(payload).attributes["source_ips"] == []


def test_native_object_ref_fields_and_stable_resource_path():
    event = normalize(native(subresource=None))
    a = event.attributes

    assert (a["resource"], a["api_group"], a["api_version"], a["namespace"], a["name"]) == \
        ("pods", "", "v1", "payments", "debug-shell")
    assert event.resource == "namespaces/payments/pods/debug-shell"
    rbac = normalize(native(request=crb(), **CRB))
    assert rbac.attributes["api_group"] == RBAC and rbac.attributes["namespace"] is None
    assert rbac.resource == "clusterrolebindings/dev-cluster-admin"


def test_native_name_falls_back_to_request_metadata():
    event = normalize(native(name=None, request=pod("gen-abc")))

    assert event.attributes["name"] == "gen-abc"


def test_gke_method_and_resource_name_parsing():
    a = normalize(gke()).attributes

    assert (a["verb"], a["resource"], a["api_group"], a["api_version"], a["namespace"], a["name"]) == \
        ("create", "pods", "", "v1", "payments", "debug-shell")
    rbac = normalize(gke("io.k8s.authorization.rbac.v1.clusterrolebindings.create",
                         "rbac.authorization.k8s.io/v1/clusterrolebindings/dev-cluster-admin")).attributes
    assert (rbac["resource"], rbac["api_group"], rbac["namespace"], rbac["name"]) == \
        ("clusterrolebindings", RBAC, None, "dev-cluster-admin")


def test_gke_subresource_and_unknown_group_handling():
    exec_call = normalize(gke("io.k8s.core.v1.pods.exec.create", "core/v1/namespaces/payments/pods/debug-shell/exec"))

    assert exec_call.attributes["subresource"] == "exec"
    assert exec_call.event_type == "k8s.audit.generic"
    other = normalize(gke("io.k8s.widgets.example.v1.gadgets.create", "widgets.example/v1/gadgets/g1")).attributes
    assert other["resource"] == "gadgets" and other["api_group"] == "widgets.example"


@pytest.mark.parametrize("method,resource_name", [
    ("", "core/v1/namespaces/payments/pods/debug-shell"),
    ("not-a-k8s-method", "x"),
    ("io.k8s.core.pods.create", "core/v1"),
    ("io.k8s.core.v1.create", ""),
    ("io.k8s..v1.pods.create", "//"),
    (None, None),
])
def test_malformed_gke_method_or_resource_name_never_crashes(method, resource_name):
    raw = gke()
    raw["protoPayload"]["methodName"] = method
    raw["protoPayload"]["resourceName"] = resource_name
    event = normalize(raw)

    assert event.event_type == "k8s.audit.generic"
    assert event.attributes["format"] == "gke"


def test_gke_resource_name_is_ignored_when_it_disagrees_with_the_method():
    a = normalize(gke("io.k8s.core.v1.pods.create", "core/v1/namespaces/other/configmaps/c1")).attributes

    assert a["resource"] == "pods" and a["namespace"] is None and a["name"] is None


def test_gke_cluster_labels():
    a = normalize(gke()).attributes

    assert (a["cluster_name"], a["cluster_location"], a["project_id"]) == ("lab-cluster", "us-central1", "cloudshield-lab")
    native_attrs = normalize(native()).attributes
    assert native_attrs["cluster_name"] is None and native_attrs["project_id"] is None


@pytest.mark.parametrize("object_ref", ["pods/payments/x", 5, [], None, {"resource": 7, "namespace": ["x"]}])
def test_malformed_object_ref_never_crashes(object_ref):
    event = normalize(native(extra={"objectRef": object_ref}, request=pod()))

    assert event.event_type == "k8s.audit.generic"
    assert event.attributes["resource"] is None


@pytest.mark.parametrize("body", ["text", 5, ["a"], {"spec": "x"}, {"spec": {"containers": 3}}, {"metadata": "x"}])
def test_malformed_request_objects_never_crash(body):
    for raw in (native(request=body), gke(request=body)):
        event = normalize(raw)
        assert event.attributes["has_privileged_container"] in (None, False)
        assert event.attributes["privileged_containers"] == []


# ---- verbs, stage and outcome -----------------------------------------------------------

@pytest.mark.parametrize("verb,expected", [("create", "create"), ("PATCH", "patch"), ("Update", "update"),
                                           ("get", "get"), ("POST", None), ("execute", None), ("", None)])
def test_verb_normalization_only_accepts_known_kubernetes_verbs(verb, expected):
    assert normalize(native(verb=verb)).attributes["verb"] == expected


@pytest.mark.parametrize("code,expected", [(200, True), (201, True), (299, True), (199, False), (300, False),
                                           (401, False), (403, False), (404, False), (409, False), (500, False),
                                           (None, None)])
def test_native_status_code_drives_operation_succeeded(code, expected):
    event = normalize(native(code=code, request=pod()))

    assert event.attributes["operation_succeeded"] is expected
    assert event.attributes["status_code"] == code
    assert (event.event_type == "k8s.audit.generic") is (expected is False)


def test_non_integer_status_code_is_unknown_not_failed():
    event = normalize(native(extra={"responseStatus": {"code": "403"}}, request=pod()))

    assert event.attributes["operation_succeeded"] is None and event.attributes["status_code"] is None
    assert normalize(native(extra={"responseStatus": {"code": True}}, request=pod())).attributes["status_code"] is None


def test_gke_rpc_status_zero_is_success_and_nonzero_is_failure():
    assert normalize(gke(request=pod(), status={"code": 0})).attributes["operation_succeeded"] is True
    failed = normalize(gke(request=pod(), status={"code": 7, "message": "Forbidden"}))
    assert failed.attributes["operation_succeeded"] is False and failed.event_type == "k8s.audit.generic"
    unknown = normalize(gke(request=pod()))
    assert unknown.attributes["operation_succeeded"] is None and unknown.event_type == "k8s.workload.change"


@pytest.mark.parametrize("stage,actionable", [("ResponseComplete", True), ("RequestReceived", False),
                                              ("ResponseStarted", False), ("Panic", False), (None, False)])
def test_only_response_complete_is_actionable_for_native_events(stage, actionable):
    event = normalize(native(stage=stage, code=None, request=pod()))

    assert event.attributes["actionable_stage"] is actionable
    assert (event.event_type == "k8s.workload.change") is actionable
    assert event.attributes["has_privileged_container"] is True  # facts are still extracted, only routing changes


def test_read_and_delete_verbs_are_never_change_events():
    for verb in ("get", "list", "watch", "delete", "deletecollection"):
        assert normalize(native(verb=verb, request=pod())).event_type == "k8s.audit.generic"


def test_event_type_routing_for_pods_and_clusterrolebindings_only():
    assert normalize(native(request=pod())).event_type == "k8s.workload.change"
    assert normalize(native(request=crb(), **CRB)).event_type == "k8s.rbac.binding_change"
    assert normalize(native(resource="rolebindings", api_group=RBAC, request=crb())).event_type == "k8s.audit.generic"
    assert normalize(native(resource="pods", api_group="example.com", request=pod())).event_type == "k8s.audit.generic"
    assert normalize(native(subresource="status", request=pod())).event_type == "k8s.audit.generic"
    assert normalize(native(resource="clusterrolebindings", namespace=None, api_group="", request=crb())
                     ).event_type == "k8s.audit.generic"


def test_timestamp_selection():
    assert normalize(native()).timestamp == "2024-08-06T09:00:01.000000Z"
    raw = native()
    del raw["stageTimestamp"]
    assert normalize(raw).timestamp == "2024-08-06T09:00:00.000000Z"
    assert normalize(gke()).timestamp == "2024-08-06T09:00:01.000000Z"
    assert kubernetes_raw_timestamp(native()) == "2024-08-06T09:00:01.000000Z"
    assert kubernetes_raw_timestamp(gke()) == "2024-08-06T09:00:01.000000Z"
    assert kubernetes_raw_timestamp("junk") is None


# ---- data handling ---------------------------------------------------------------------------

def test_request_object_is_compact_and_never_contains_specs_or_secret_data():
    body = pod()
    body["spec"]["containers"][0]["env"] = [{"name": "TOKEN", "value": "SECRET-VALUE"}]
    event = normalize(native(request=body))
    rendered = json.dumps(event.attributes)

    assert event.attributes["request_object"] == {"kind": "Pod", "apiVersion": "v1", "name": "debug-shell",
                                                  "namespace": "payments"}
    assert "SECRET-VALUE" not in rendered and "image" not in rendered


def test_secret_objects_are_never_copied_and_responses_are_never_read():
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db", "namespace": "payments"},
              "data": {"password": "U0VDUkVU"}, "stringData": {"p": "SECRET-VALUE"}}
    raw = native(verb="create", resource="secrets", name="db", request=secret,
                 extra={"responseObject": {"kind": "Secret", "data": {"password": "U0VDUkVU"}}})
    event = normalize(raw)
    rendered = json.dumps({"a": event.attributes, "r": event.resource, "p": event.principal})

    assert event.attributes["request_object"] is None
    assert "U0VDUkVU" not in rendered and "SECRET-VALUE" not in rendered


def test_normalization_does_not_mutate_input():
    for raw in (native(request=pod()), gke(request=pod()), native(request=crb(), **CRB)):
        before = copy.deepcopy(raw)
        normalize(raw)
        assert raw == before


# ---- telemetry registry -------------------------------------------------------------------------

def test_registry_dispatches_by_type_and_rejects_unknown_types():
    assert set(ADAPTERS) == {"gcp_audit", "kubernetes_audit"}
    assert get_adapter("kubernetes_audit").normalize(native()).source == "kubernetes_audit"
    assert get_adapter("gcp_audit").normalize({"protoPayload": {}}).source == "gcp_audit"
    for bad in ("kubernetes", "", None, "GCP_AUDIT"):
        with pytest.raises(ValueError, match="Unknown telemetry_type"):
            get_adapter(bad)


# ---- raw telemetry is input-only (Secret-bearing events) ---------------------------------------------

FAKE_SECRET_VALUE = "FAKE-SECRET-VALUE-do-not-use"
FAKE_TOKEN_VALUE = "FAKE-TOKEN-VALUE-do-not-use"
FAKE_KEY_VALUE = "FAKE-PRIVATE-KEY-MATERIAL-do-not-use"
SENTINELS = (FAKE_SECRET_VALUE, FAKE_TOKEN_VALUE, FAKE_KEY_VALUE, "ZmFrZS1zZWNyZXQ=")


def _secret(**fields):
    return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "db-credentials", "namespace": "payments"},
            "type": "Opaque", **fields}


def _everything(event):
    """All text reachable from a NormalizedEvent, including raw."""
    return json.dumps({"source": event.source, "type": event.event_type, "timestamp": event.timestamp,
                       "principal": event.principal, "resource": event.resource, "attributes": event.attributes,
                       "raw": event.raw}, default=str)


def _assert_no_sentinels(event):
    text = _everything(event)
    for sentinel in SENTINELS:
        assert sentinel not in text, sentinel


def test_native_secret_data_is_not_retained():
    body = _secret(data={"password": "ZmFrZS1zZWNyZXQ="})
    raw = native(resource="secrets", name="db-credentials", request=body,
                 extra={"responseObject": _secret(data={"password": "ZmFrZS1zZWNyZXQ="})})
    event = normalize(raw)

    _assert_no_sentinels(event)
    assert event.attributes["request_object"] is None
    assert event.attributes["name"] == "db-credentials" and event.attributes["namespace"] == "payments"


def test_native_secret_string_data_is_not_retained():
    raw = native(resource="secrets", name="db-credentials", request=_secret(stringData={"password": FAKE_SECRET_VALUE}),
                 extra={"responseObject": _secret(stringData={"password": FAKE_SECRET_VALUE})})

    _assert_no_sentinels(normalize(raw))


def test_gke_secret_data_is_not_retained():
    request = _secret(data={"password": "ZmFrZS1zZWNyZXQ="})
    event = normalize(gke("io.k8s.core.v1.secrets.create", "core/v1/namespaces/payments/secrets/db-credentials",
                          request=request))

    _assert_no_sentinels(event)
    assert event.attributes["request_object"] is None and event.attributes["resource"] == "secrets"


def test_gke_secret_string_data_is_not_retained():
    request = _secret(stringData={"password": FAKE_SECRET_VALUE})
    event = normalize(gke("io.k8s.core.v1.secrets.update", "core/v1/namespaces/payments/secrets/db-credentials",
                          request=request))

    _assert_no_sentinels(event)


def test_tokens_and_keys_in_any_part_of_the_raw_event_are_not_retained():
    raw = native(request=pod(), extra={
        "annotations": {"note": FAKE_TOKEN_VALUE},
        "responseObject": {"kind": "Pod", "status": {"token": FAKE_TOKEN_VALUE}},
        "requestObject": {**pod(), "metadata": {"name": "debug-shell", "namespace": "payments",
                                                "annotations": {"key": FAKE_KEY_VALUE, "bearer": FAKE_TOKEN_VALUE}}},
        "userAgent": "kubectl/v1.30.0"})
    gke_raw = gke(request={**pod(), "spec": {"containers": [{"name": "debug-shell", "env": [
        {"name": "PRIVATE_KEY", "value": FAKE_KEY_VALUE}], "securityContext": {"privileged": True}}]}},
        status={"code": 0, "message": FAKE_TOKEN_VALUE})

    for candidate in (raw, gke_raw):
        _assert_no_sentinels(normalize(candidate))


@pytest.mark.parametrize("raw", [
    native(request=pod()), gke(request=pod()), native(request=crb(), **CRB),
    native(resource="secrets", name="s", request=_secret(data={"k": FAKE_SECRET_VALUE})),
    {}, {"protoPayload": {"serviceName": "iam.googleapis.com"}, "resource": {"type": "project"}},
    "text", None, [1, 2], native(extra={"objectRef": "junk"}),
])
def test_normalized_event_never_retains_the_original_object(raw):
    event = normalize(raw)

    assert event.raw == {}
    assert event.raw is not raw


def test_normalized_event_keeps_useful_forensic_fields_without_raw():
    event = normalize(gke(request=pod(containers=[{"name": "agent", "securityContext": {"privileged": True}}]),
                          labels={"project_id": "cloudshield-lab", "cluster_name": "lab-cluster",
                                  "location": "us-central1"}))
    a = event.attributes

    assert event.principal == "developer@example.com" and event.event_type == "k8s.workload.change"
    assert event.timestamp and event.resource == "namespaces/payments/pods/debug-shell"
    assert (a["verb"], a["api_group"], a["api_version"], a["namespace"], a["name"], a["subresource"]) == \
        ("create", "", "v1", "payments", "debug-shell", None)
    assert a["source_ips"] == ["203.0.113.10"] and a["user_agent"] == "kubectl/v1.30.0"
    assert (a["cluster_name"], a["cluster_location"], a["project_id"]) == ("lab-cluster", "us-central1", "cloudshield-lab")
    assert a["privileged_containers"] == ["agent"] and a["operation_succeeded"] is None
    native_attrs = normalize(native(request=crb(), **CRB)).attributes
    assert native_attrs["stage"] == "ResponseComplete" and native_attrs["status_code"] == 201
    assert native_attrs["rbac_role_ref_name"] == "cluster-admin"
    assert native_attrs["rbac_subjects"] == [{"kind": "User", "name": "developer@example.com"}]
    assert native_attrs["request_object"] == {"kind": "ClusterRoleBinding", "apiVersion": None,
                                              "name": "dev-cluster-admin", "namespace": None}


def test_findings_never_carry_raw_telemetry():
    from cloudshield.engine.evaluator import evaluate_rule
    from cloudshield.engine.rule_loader import load_rule
    import os

    rule = load_rule(os.path.join(os.path.dirname(__file__), "..", "rules", "kubernetes", "privileged_pod.yaml"))
    raw = native(request=pod(), extra={"responseObject": {"leak": FAKE_TOKEN_VALUE}})
    finding = evaluate_rule(rule, normalize(raw))

    assert finding is not None
    assert FAKE_TOKEN_VALUE not in json.dumps(finding.evidence, default=str)
