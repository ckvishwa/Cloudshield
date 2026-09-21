import copy
import json
import os

import pytest
import yaml

from cloudshield.engine.evaluator import evaluate_rule
from cloudshield.engine.rule_loader import load_rule, load_rules
from cloudshield.engine.runner import run_event
from cloudshield.telemetry.gcp_audit import normalize_gcp_audit_event

RULE_DIR = os.path.join(os.path.dirname(__file__), "..", "rules", "iam")
IAM_001 = os.path.join(RULE_DIR, "privilege_escalation.yaml")
IAM_003 = os.path.join(RULE_DIR, "policy_snapshot_high_risk_role.yaml")
HIGH_RISK = ["roles/owner", "roles/editor", "roles/iam.securityAdmin",
             "roles/resourcemanager.projectIamAdmin", "roles/iam.serviceAccountAdmin"]


def _binding(role, *members):
    return {"role": role, "members": list(members)}


def _event(method="SetIamPolicy", response=None, request_policy=None, deltas=None, principal="admin@example.com",
           ip="203.0.113.21", resource="projects/cloudshield-lab", extra=None):
    payload = {"serviceName": "cloudresourcemanager.googleapis.com", "resourceName": resource,
               "requestMetadata": {"callerIp": ip}}
    if method is not None:
        payload["methodName"] = method
    if principal is not None:
        payload["authenticationInfo"] = {"principalEmail": principal}
    if response is not None:
        payload["response"] = response
    if request_policy is not None:
        payload["request"] = {"policy": request_policy}
    if deltas is not None:
        payload["metadata"] = {"bindingDeltas": deltas}
    payload.update(extra or {})
    return {"timestamp": "2024-08-05T10:00:00.000000Z", "protoPayload": payload}


def _norm(**kwargs):
    return normalize_gcp_audit_event(_event(**kwargs))


def _iam_003(event):
    return evaluate_rule(load_rule(IAM_003), event)


def _iam_001(event):
    return evaluate_rule(load_rule(IAM_001), event)


# ---- method recognition ---------------------------------------------------------

@pytest.mark.parametrize("method", [
    "SetIamPolicy",
    "google.iam.admin.v1.SetIAMPolicy",
    "google.iam.v1.SetIamPolicy",
    "google.iam.v1.IAMPolicy.SetIamPolicy",
    "v1.compute.projects.setIamPolicy",
])
def test_set_iam_policy_variants_are_policy_changes_without_deltas(method):
    event = _norm(method=method)

    assert event.event_type == "gcp.iam.policy_change"
    assert event.attributes["policy_delta_present"] is False
    assert event.attributes["roles_added"] == [] and event.attributes["roles_removed"] == []
    assert event.attributes["policy_snapshot_source"] is None
    assert event.attributes["roles_present_after"] == []


@pytest.mark.parametrize("method", [
    "NotSetIamPolicy", "SetIamPolicyPreview", "SomeSetIamPolicyOtherOperation",
    "google.iam.v1.SetIamPolicyExtra", "SetIamPolicy.Extra", "TestIamPermissions", "", None,
])
def test_near_miss_methods_are_not_policy_changes(method):
    event = _norm(method=method, response={"bindings": [_binding("roles/owner", "user:a@example.com")]})

    assert event.event_type == "gcp.audit.generic"
    assert "roles_present_after" not in event.attributes
    assert _iam_003(event) is None


def test_unrelated_method_with_response_bindings_is_not_a_policy_change():
    event = _norm(method="storage.buckets.update",
                  response={"bindings": [_binding("roles/owner", "user:a@example.com")]})

    assert event.event_type == "gcp.audit.generic"
    assert _iam_003(event) is None


def test_binding_deltas_still_make_a_policy_change_on_any_method():
    event = _norm(method=None, deltas=[{"action": "ADD", "role": "roles/owner", "member": "user:a@example.com"}])

    assert event.event_type == "gcp.iam.policy_change"
    assert event.attributes["roles_added"] == ["roles/owner"]


# ---- snapshot extraction --------------------------------------------------------

def test_response_policy_roles_are_extracted():
    event = _norm(response={"bindings": [_binding("roles/viewer", "user:a@example.com"),
                                         _binding("roles/owner", "user:b@example.com")]})

    assert event.attributes["policy_snapshot_source"] == "response"
    assert event.attributes["roles_present_after"] == ["roles/viewer", "roles/owner"]
    assert event.attributes["bindings_present_after"] == [
        {"role": "roles/viewer", "members": ["user:a@example.com"]},
        {"role": "roles/owner", "members": ["user:b@example.com"]}]


def test_request_policy_is_the_fallback_source():
    event = _norm(request_policy={"bindings": [_binding("roles/owner", "user:a@example.com")]})

    assert event.attributes["policy_snapshot_source"] == "request"
    assert event.attributes["roles_present_after"] == ["roles/owner"]


def test_response_is_preferred_over_request_and_they_are_never_merged():
    event = _norm(response={"bindings": [_binding("roles/viewer", "user:a@example.com")]},
                  request_policy={"bindings": [_binding("roles/owner", "user:b@example.com")]})

    assert event.attributes["policy_snapshot_source"] == "response"
    assert event.attributes["roles_present_after"] == ["roles/viewer"]
    assert _iam_003(event) is None


def test_empty_response_policy_is_still_the_response_source():
    event = _norm(response={"bindings": []},
                  request_policy={"bindings": [_binding("roles/owner", "user:b@example.com")]})

    assert event.attributes["policy_snapshot_source"] == "response"
    assert event.attributes["roles_present_after"] == []


def test_unusable_response_bindings_fall_back_to_request():
    event = _norm(response={"bindings": "not-a-list"},
                  request_policy={"bindings": [_binding("roles/owner", "user:b@example.com")]})

    assert event.attributes["policy_snapshot_source"] == "request"


def test_snapshot_never_populates_roles_added():
    event = _norm(response={"bindings": [_binding("roles/owner", "user:a@example.com")]})

    assert event.attributes["roles_added"] == []
    assert event.attributes["bindings_added"] == []
    assert event.attributes["roles_removed"] == []
    assert _iam_001(event) is None


def test_only_needed_snapshot_fields_are_copied():
    response = {"@type": "type.googleapis.com/google.iam.v1.Policy", "etag": "BwXabc", "version": 3,
                "auditConfigs": [{"service": "allServices"}],
                "bindings": [{"role": "roles/owner", "members": ["user:a@example.com"],
                              "condition": {"expression": "true"}}]}
    event = _norm(response=response, extra={"authorizationInfo": [{"permission": "x"}]})
    rendered = json.dumps(event.attributes)

    for leaked in ("etag", "BwXabc", "auditConfigs", "condition", "authorizationInfo", "@type"):
        assert leaked not in rendered
    assert event.attributes["bindings_present_after"] == [{"role": "roles/owner", "members": ["user:a@example.com"]}]


def test_duplicate_roles_are_listed_once_but_bindings_are_kept():
    event = _norm(response={"bindings": [_binding("roles/owner", "user:a@example.com"),
                                         _binding("roles/owner", "user:b@example.com")]})

    assert event.attributes["roles_present_after"] == ["roles/owner"]
    assert len(event.attributes["bindings_present_after"]) == 2


# ---- malformed input ------------------------------------------------------------

@pytest.mark.parametrize("response", [
    "a string", 42, ["list"], {"bindings": "a string"}, {"bindings": {"role": "roles/owner"}},
    {"bindings": [None, 7, "roles/owner"]}, {"bindings": [{"role": ["roles/owner"], "members": ["user:a@example.com"]}]},
    {"bindings": [{"role": "roles/owner", "members": "user:a@example.com"}]},
    {"bindings": [{"role": "roles/owner", "members": [None, 5, {"x": 1}]}]},
    {"bindings": [{"role": "roles/owner"}]}, {"bindings": [{"members": ["user:a@example.com"]}]},
    {"bindings": [{"role": "", "members": ["user:a@example.com"]}]},
])
def test_malformed_response_snapshots_do_not_crash_or_invent_roles(response):
    event = _norm(response=response)

    assert event.event_type == "gcp.iam.policy_change"
    assert event.attributes["roles_present_after"] == []
    assert event.attributes["roles_added"] == []
    assert _iam_003(event) is None and _iam_001(event) is None


@pytest.mark.parametrize("request_policy", ["str", 5, {"bindings": "x"}, {"bindings": [None, "x", 1]}, {}])
def test_malformed_request_policies_do_not_crash_or_invent_roles(request_policy):
    event = _norm(request_policy=request_policy)

    assert event.attributes["roles_present_after"] == []
    assert _iam_003(event) is None


def test_malformed_request_field_does_not_crash():
    event = normalize_gcp_audit_event(_event(extra={"request": "not-an-object"}))

    assert event.event_type == "gcp.iam.policy_change"
    assert event.attributes["policy_snapshot_source"] is None


def test_non_string_members_are_dropped_and_string_members_kept():
    event = _norm(response={"bindings": [_binding("roles/owner", "user:a@example.com", None, 5)]})

    assert event.attributes["bindings_present_after"] == [{"role": "roles/owner", "members": ["user:a@example.com"]}]


def test_missing_method_name_with_snapshot_is_not_a_policy_change():
    event = _norm(method=None, response={"bindings": [_binding("roles/owner", "user:a@example.com")]})

    assert event.event_type == "gcp.audit.generic"


# ---- GCP-IAM-003 detection --------------------------------------------------------

@pytest.mark.parametrize("role", HIGH_RISK)
def test_iam_003_fires_for_each_high_risk_role_in_a_snapshot(role):
    finding = _iam_003(_norm(response={"bindings": [_binding(role, "user:a@example.com")]}))

    assert finding is not None
    assert finding.rule_id == "GCP-IAM-003"
    assert finding.severity == "MEDIUM"
    assert finding.mitre_attack == "T1098"
    assert finding.matched_values["attributes.roles_present_after"] == [role]


def test_iam_003_owner_snapshot_full_evidence():
    event = _norm(response={"bindings": [_binding("roles/owner", "user:b@example.com")]})
    finding = _iam_003(event)

    assert finding.principal == "admin@example.com"
    assert finding.resource == "projects/cloudshield-lab"
    assert finding.source_ip == "203.0.113.21"
    assert finding.method_name == "SetIamPolicy"
    assert finding.timestamp == "2024-08-05T10:00:00.000000Z"
    assert finding.evidence["matched_bindings"] == [{"role": "roles/owner", "members": ["user:b@example.com"]}]
    attributes = finding.evidence["event_attributes"]
    assert attributes["policy_snapshot_source"] == "response"
    assert attributes["policy_delta_present"] is False
    assert attributes["roles_added"] == []


def test_iam_003_request_fallback_preserves_snapshot_source():
    finding = _iam_003(_norm(request_policy={"bindings": [_binding("roles/owner", "user:a@example.com")]}))

    assert finding.evidence["event_attributes"]["policy_snapshot_source"] == "request"


def test_iam_003_matched_binding_carries_only_the_matching_role_members():
    event = _norm(response={"bindings": [_binding("roles/viewer", "user:a@example.com"),
                                         _binding("roles/owner", "user:b@example.com", "group:ops@example.com"),
                                         _binding("roles/browser", "user:c@example.com")]})
    finding = _iam_003(event)

    assert finding.matched_values["attributes.roles_present_after"] == ["roles/owner"]
    assert finding.evidence["matched_bindings"] == [
        {"role": "roles/owner", "members": ["user:b@example.com", "group:ops@example.com"]}]
    assert "user:a@example.com" not in json.dumps(finding.evidence["matched_bindings"])


def test_iam_003_multiple_high_risk_roles_each_keep_their_own_members():
    event = _norm(response={"bindings": [_binding("roles/editor", "user:e@example.com"),
                                         _binding("roles/owner", "user:o@example.com")]})
    finding = _iam_003(event)

    assert finding.matched_values["attributes.roles_present_after"] == ["roles/editor", "roles/owner"]
    assert {b["role"]: b["members"] for b in finding.evidence["matched_bindings"]} == {
        "roles/editor": ["user:e@example.com"], "roles/owner": ["user:o@example.com"]}


def test_iam_003_viewer_and_custom_role_snapshots_do_not_fire():
    assert _iam_003(_norm(response={"bindings": [_binding("roles/viewer", "user:a@example.com")]})) is None
    custom = _binding("projects/cloudshield-lab/roles/customOwner", "user:a@example.com")
    assert _iam_003(_norm(response={"bindings": [custom]})) is None


def test_iam_003_role_id_matching_is_exact():
    for role in ("roles/Owner", "roles/owner ", "roles/owners", "owner"):
        assert _iam_003(_norm(response={"bindings": [_binding(role, "user:a@example.com")]})) is None


def test_iam_003_missing_principal_and_ip_do_not_crash():
    event = normalize_gcp_audit_event(_event(response={"bindings": [_binding("roles/owner", "user:a@example.com")]},
                                             principal=None, ip=None))
    finding = _iam_003(event)

    assert finding is not None
    assert finding.principal is None
    assert finding.source_ip is None


def test_iam_003_source_ip_preserved():
    finding = _iam_003(normalize_gcp_audit_event(
        _event(response={"bindings": [_binding("roles/owner", "user:a@example.com")]}, ip="198.51.100.9")))

    assert finding.source_ip == "198.51.100.9"


# ---- signal precedence: delta vs snapshot ---------------------------------------

def test_delta_plus_snapshot_fires_iam_001_only():
    event = _norm(deltas=[{"action": "ADD", "role": "roles/owner", "member": "user:a@example.com"}],
                  response={"bindings": [_binding("roles/owner", "user:a@example.com")]})

    assert event.attributes["policy_delta_present"] is True
    assert event.attributes["policy_snapshot_source"] == "response"
    assert _iam_001(event) is not None
    assert _iam_003(event) is None


def test_remove_only_delta_still_counts_as_a_delta_and_suppresses_iam_003():
    event = _norm(deltas=[{"action": "REMOVE", "role": "roles/viewer", "member": "user:a@example.com"}],
                  response={"bindings": [_binding("roles/owner", "user:b@example.com")]})

    assert event.attributes["policy_delta_present"] is True
    assert _iam_003(event) is None


def test_malformed_deltas_are_not_usable_so_the_snapshot_signal_remains():
    event = _norm(deltas=["garbage", None, {"action": "GRANT", "role": "roles/owner"}, {"action": "ADD"}],
                  response={"bindings": [_binding("roles/owner", "user:a@example.com")]})

    assert event.attributes["policy_delta_present"] is False
    assert event.attributes["roles_added"] == []
    assert _iam_001(event) is None
    assert _iam_003(event) is not None


def test_run_event_with_repo_rules_never_double_alerts_on_one_change():
    rules = load_rules(os.path.join(os.path.dirname(__file__), "..", "rules"))
    with_delta = _norm(deltas=[{"action": "ADD", "role": "roles/owner", "member": "user:a@example.com"}],
                       response={"bindings": [_binding("roles/owner", "user:a@example.com")]})
    snapshot_only = _norm(response={"bindings": [_binding("roles/owner", "user:a@example.com")]})

    assert [f.rule_id for f in run_event(with_delta, rules)] == ["GCP-IAM-001"]
    assert [f.rule_id for f in run_event(snapshot_only, rules)] == ["GCP-IAM-003"]


# ---- existing behavior unchanged ---------------------------------------------------

def test_iam_001_still_uses_only_add_deltas_and_correlates_members():
    event = _norm(deltas=[{"action": "ADD", "role": "roles/viewer", "member": "user:a@example.com"},
                          {"action": "ADD", "role": "roles/owner", "member": "user:b@example.com"},
                          {"action": "REMOVE", "role": "roles/editor", "member": "user:c@example.com"}])
    finding = _iam_001(event)

    assert finding.matched_values == {"attributes.roles_added": ["roles/owner"]}
    assert finding.evidence["matched_bindings"] == [{"role": "roles/owner", "member": "user:b@example.com"}]
    assert event.attributes["roles_removed"] == ["roles/editor"]


def test_iam_002_credential_events_are_unaffected():
    raw = {"timestamp": "2024-08-05T10:00:00Z",
           "resource": {"labels": {"email_id": "prod-admin@cloudshield-lab.iam.gserviceaccount.com"}},
           "protoPayload": {"serviceName": "iamcredentials.googleapis.com", "methodName": "GenerateAccessToken",
                            "authenticationInfo": {"principalEmail": "developer@example.com"},
                            "response": {"bindings": [_binding("roles/owner", "user:a@example.com")]}}}
    event = normalize_gcp_audit_event(raw)

    assert event.event_type == "gcp.iam.service_account_credential_generation"
    assert "roles_present_after" not in event.attributes
    assert event.attributes["target_service_account"] == "prod-admin@cloudshield-lab.iam.gserviceaccount.com"


def test_normalization_does_not_mutate_the_input():
    raw = _event(response={"bindings": [_binding("roles/owner", "user:a@example.com")]},
                 request_policy={"bindings": []}, deltas=[{"action": "ADD", "role": "roles/x", "member": "user:a@example.com"}])
    before = copy.deepcopy(raw)
    normalize_gcp_audit_event(raw)

    assert raw == before


# ---- rule consistency -----------------------------------------------------------------

def _condition_values(path, field):
    with open(path, encoding="utf-8") as handle:
        rule = yaml.safe_load(handle)
    return next(c["value"] for c in rule["conditions"] if c["field"] == field)


def test_iam_001_and_iam_003_high_risk_role_lists_are_identical():
    iam_001 = _condition_values(IAM_001, "attributes.roles_added")
    iam_003 = _condition_values(IAM_003, "attributes.roles_present_after")

    assert iam_001 == iam_003
    assert sorted(iam_003) == sorted(HIGH_RISK)


def test_iam_003_requires_the_no_delta_condition():
    conditions = load_rule(IAM_003).conditions

    assert {"field": "attributes.policy_delta_present", "operator": "equals", "value": False} in conditions


def test_repository_rules_include_the_three_iam_rules():
    ids = [r.rule_id for r in load_rules(os.path.join(os.path.dirname(__file__), "..", "rules"))]

    assert {"GCP-IAM-001", "GCP-IAM-002", "GCP-IAM-003"} <= set(ids)
