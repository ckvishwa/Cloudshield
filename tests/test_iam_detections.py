import pytest
from cloudshield.models import NormalizedEvent, DetectionRule
from cloudshield.telemetry.gcp_audit import normalize_gcp_audit_event
from cloudshield.engine.rule_loader import load_rule
from cloudshield.engine.evaluator import evaluate_rule
import os

def test_gcp_iam_001_true_positive():
    raw_event = {
        "protoPayload": {
            "authenticationInfo": {
                "principalEmail": "attacker@example.com"
            },
            "resourceName": "projects/cloudshield-lab",
            "methodName": "SetIamPolicy",
            "metadata": {
                "bindingDeltas": [
                    {
                        "action": "ADD",
                        "role": "roles/owner",
                        "member": "user:attacker@example.com"
                    }
                ]
            }
        },
        "timestamp": "2023-10-27T12:00:00Z"
    }

    event = normalize_gcp_audit_event(raw_event)
    rule_path = os.path.join(os.path.dirname(__file__), "..", "rules", "iam", "privilege_escalation.yaml")
    rule = load_rule(rule_path)
    finding = evaluate_rule(rule, event)

    assert finding is not None
    assert finding.rule_id == "GCP-IAM-001"
    assert finding.severity == "HIGH"
    assert finding.principal == "attacker@example.com"
    assert "roles/owner" in finding.evidence["event_attributes"]["roles_added"]

def test_gcp_iam_001_false_positive_control():
    raw_event = {
        "protoPayload": {
            "authenticationInfo": {
                "principalEmail": "admin@example.com"
            },
            "resourceName": "projects/cloudshield-lab",
            "methodName": "SetIamPolicy",
            "metadata": {
                "bindingDeltas": [
                    {
                        "action": "ADD",
                        "role": "roles/viewer",
                        "member": "user:newhire@example.com"
                    }
                ]
            }
        },
        "timestamp": "2023-10-27T12:00:00Z"
    }

    event = normalize_gcp_audit_event(raw_event)
    rule_path = os.path.join(os.path.dirname(__file__), "..", "rules", "iam", "privilege_escalation.yaml")
    rule = load_rule(rule_path)
    finding = evaluate_rule(rule, event)

    assert finding is None

def test_gcp_iam_001_remove_dangerous_role_does_not_trigger():
    raw_event = {
        "protoPayload": {
            "authenticationInfo": {
                "principalEmail": "admin@example.com"
            },
            "resourceName": "projects/cloudshield-lab",
            "metadata": {
                "bindingDeltas": [
                    {
                        "action": "REMOVE",
                        "role": "roles/owner",
                        "member": "user:ex_employee@example.com"
                    }
                ]
            }
        }
    }

    event = normalize_gcp_audit_event(raw_event)
    rule_path = os.path.join(os.path.dirname(__file__), "..", "rules", "iam", "privilege_escalation.yaml")
    rule = load_rule(rule_path)
    finding = evaluate_rule(rule, event)

    assert finding is None

def test_normalize_gcp_audit_service_data():
    raw_event = {
        "protoPayload": {
            "serviceData": {
                "policyDelta": {
                    "bindingDeltas": [
                        {
                            "action": "ADD",
                            "role": "roles/editor"
                        }
                    ]
                }
            }
        }
    }
    
    event = normalize_gcp_audit_event(raw_event)
    assert event.event_type == "gcp.iam.policy_change"
    assert "roles/editor" in event.attributes.get("roles_added", [])

def test_normalize_gcp_audit_malformed_deltas():
    raw_event = {
        "protoPayload": {
            "metadata": {
                "bindingDeltas": [
                    "this is a string, not a dict",
                    None,
                    {"action": "ADD", "role": "roles/owner"}
                ]
            }
        }
    }
    
    event = normalize_gcp_audit_event(raw_event)
    assert event.event_type == "gcp.iam.policy_change"
    assert "roles/owner" in event.attributes.get("roles_added", [])

def test_missing_metadata_does_not_crash():
    raw_event = {
        "protoPayload": {}
    }
    event = normalize_gcp_audit_event(raw_event)
    assert event.event_type == "gcp.audit.generic"


RULE_PATH = os.path.join(os.path.dirname(__file__), "..", "rules", "iam", "privilege_escalation.yaml")


def _policy_change(*deltas):
    return {
        "protoPayload": {
            "authenticationInfo": {"principalEmail": "admin@example.com"},
            "resourceName": "projects/cloudshield-lab",
            "metadata": {"bindingDeltas": list(deltas)},
        },
        "timestamp": "2023-10-27T12:00:00Z",
    }


def test_gcp_iam_001_missing_optional_fields_does_not_crash():
    raw_event = {
        "protoPayload": {
            "metadata": {"bindingDeltas": [{"action": "ADD", "role": "roles/owner"}]}
        }
    }
    event = normalize_gcp_audit_event(raw_event)
    finding = evaluate_rule(load_rule(RULE_PATH), event)

    assert event.principal is None
    assert event.resource is None
    assert event.timestamp is None
    assert finding is not None
    assert finding.principal is None
    assert finding.resource is None
    assert finding.timestamp is None


def test_gcp_iam_001_malformed_delta_alone_does_not_trigger():
    raw_event = _policy_change(
        "roles/owner",
        None,
        42,
        {"action": "ADD"},
        {"action": "ADD", "role": None},
        {"action": "ADD", "role": ["roles/owner"]},
        {"action": "ADD", "role": {"name": "roles/owner"}},
        {"role": "roles/owner"},
        {"action": "GRANT", "role": "roles/owner"},
    )
    event = normalize_gcp_audit_event(raw_event)

    assert event.attributes["roles_added"] == []
    assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_gcp_iam_001_malformed_delta_does_not_mask_valid_one():
    raw_event = _policy_change("garbage", {"action": "ADD", "role": "roles/owner"})
    event = normalize_gcp_audit_event(raw_event)

    assert evaluate_rule(load_rule(RULE_PATH), event) is not None


def test_gcp_iam_001_non_dict_payload_does_not_crash():
    for raw_event in ({}, {"protoPayload": None}, {"protoPayload": "x"},
                      {"protoPayload": {"metadata": "x", "serviceData": []}}):
        event = normalize_gcp_audit_event(raw_event)
        assert event.event_type == "gcp.audit.generic"
        assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_gcp_iam_001_wrong_source_does_not_trigger():
    event = normalize_gcp_audit_event(
        _policy_change({"action": "ADD", "role": "roles/owner"})
    )
    event.source = "kubernetes_audit"

    assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_gcp_iam_001_wrong_event_type_does_not_trigger():
    raw_event = {"protoPayload": {"resourceName": "projects/cloudshield-lab"}}
    event = normalize_gcp_audit_event(raw_event)

    assert event.event_type == "gcp.audit.generic"
    assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_gcp_iam_001_duplicate_roles_and_mixed_add_remove():
    raw_event = _policy_change(
        {"action": "ADD", "role": "roles/owner"},
        {"action": "ADD", "role": "roles/owner"},
        {"action": "REMOVE", "role": "roles/viewer"},
    )
    event = normalize_gcp_audit_event(raw_event)
    finding = evaluate_rule(load_rule(RULE_PATH), event)

    assert finding is not None
    assert finding.evidence["event_attributes"]["roles_removed"] == ["roles/viewer"]


def test_gcp_iam_001_near_miss_role_does_not_trigger():
    raw_event = _policy_change(
        {"action": "ADD", "role": "roles/owner-readonly"},
        {"action": "ADD", "role": "roles/Owner"},
    )
    event = normalize_gcp_audit_event(raw_event)

    assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_evaluate_rule_unsupported_operator_raises():
    rule = DetectionRule(
        rule_id="TEST-001",
        title="Bad operator",
        severity="LOW",
        source="gcp_audit",
        event_type="gcp.iam.policy_change",
        conditions=[
            {"field": "attributes.roles_added", "operator": "regex_match", "value": ["x"]}
        ],
    )
    event = normalize_gcp_audit_event(
        _policy_change({"action": "ADD", "role": "roles/owner"})
    )

    with pytest.raises(ValueError, match="Unknown operator: regex_match"):
        evaluate_rule(rule, event)


def test_evaluate_rule_incomplete_condition_raises():
    rule = DetectionRule(
        rule_id="TEST-002",
        title="Incomplete condition",
        severity="LOW",
        source="gcp_audit",
        event_type="gcp.iam.policy_change",
        conditions=[{"field": "attributes.roles_added", "operator": "contains_any"}],
    )
    event = normalize_gcp_audit_event(
        _policy_change({"action": "ADD", "role": "roles/owner"})
    )

    with pytest.raises(ValueError):
        evaluate_rule(rule, event)


def _full_event(*deltas, caller_ip="203.0.113.7"):
    raw = _policy_change(*deltas)
    raw["protoPayload"]["methodName"] = "SetIamPolicy"
    if caller_ip is not None:
        raw["protoPayload"]["requestMetadata"] = {"callerIp": caller_ip}
    return raw


def test_gcp_iam_001_finding_records_matched_role():
    event = normalize_gcp_audit_event(
        _full_event({"action": "ADD", "role": "roles/owner", "member": "user:b@example.com"})
    )
    finding = evaluate_rule(load_rule(RULE_PATH), event)

    assert finding.matched_values == {"attributes.roles_added": ["roles/owner"]}


def test_gcp_iam_001_mixed_bindings_match_only_dangerous_role():
    event = normalize_gcp_audit_event(_full_event(
        {"action": "ADD", "role": "roles/viewer", "member": "user:a@example.com"},
        {"action": "ADD", "role": "roles/owner", "member": "user:b@example.com"},
    ))
    finding = evaluate_rule(load_rule(RULE_PATH), event)

    assert finding.matched_values == {"attributes.roles_added": ["roles/owner"]}
    assert "roles/viewer" in finding.evidence["event_attributes"]["roles_added"]


def test_gcp_iam_001_member_correlated_with_owner_grant_only():
    event = normalize_gcp_audit_event(_full_event(
        {"action": "ADD", "role": "roles/viewer", "member": "user:a@example.com"},
        {"action": "ADD", "role": "roles/owner", "member": "user:b@example.com"},
    ))
    finding = evaluate_rule(load_rule(RULE_PATH), event)

    assert finding.evidence["matched_bindings"] == [
        {"role": "roles/owner", "member": "user:b@example.com"}
    ]


def test_gcp_iam_001_caller_ip_and_operation_preserved():
    event = normalize_gcp_audit_event(
        _full_event({"action": "ADD", "role": "roles/owner", "member": "user:b@example.com"})
    )
    finding = evaluate_rule(load_rule(RULE_PATH), event)

    assert event.attributes["source_ip"] == "203.0.113.7"
    assert finding.source_ip == "203.0.113.7"
    assert finding.method_name == "SetIamPolicy"


def test_gcp_iam_001_timestamp_and_context_preserved():
    event = normalize_gcp_audit_event(
        _full_event({"action": "ADD", "role": "roles/owner", "member": "user:b@example.com"})
    )
    finding = evaluate_rule(load_rule(RULE_PATH), event)

    assert finding.timestamp == "2023-10-27T12:00:00Z"
    assert finding.principal == "admin@example.com"
    assert finding.resource == "projects/cloudshield-lab"
    assert finding.mitre_attack == "T1098"


def test_gcp_iam_001_missing_caller_ip_and_member_are_none():
    event = normalize_gcp_audit_event(
        _policy_change({"action": "ADD", "role": "roles/owner"})
    )
    finding = evaluate_rule(load_rule(RULE_PATH), event)

    assert finding is not None
    assert finding.source_ip is None
    assert finding.method_name is None
    assert finding.evidence["matched_bindings"] == [{"role": "roles/owner", "member": None}]
