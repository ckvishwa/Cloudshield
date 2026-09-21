import copy
import json
import os

import pytest

from cloudshield.engine.evaluator import evaluate_rule
from cloudshield.engine.rule_loader import load_rule
from cloudshield.telemetry.gcp_audit import normalize_gcp_audit_event

RULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "rules", "iam", "service_account_impersonation.yaml"
)
EVENT_TYPE = "gcp.iam.service_account_credential_generation"
PROTECTED = "prod-admin@cloudshield-lab.iam.gserviceaccount.com"
ALLOWED = "ci-deployer@cloudshield-lab.iam.gserviceaccount.com"
UNPROTECTED = "dev-worker@cloudshield-lab.iam.gserviceaccount.com"


def _event(method="GenerateAccessToken", principal="developer@example.com", target=PROTECTED):
    return {
        "timestamp": "2023-10-27T12:00:00Z",
        "resource": {"type": "service_account", "labels": {"email_id": target}},
        "protoPayload": {
            "serviceName": "iamcredentials.googleapis.com",
            "methodName": method,
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": "203.0.113.7"},
            "resourceName": f"projects/-/serviceAccounts/{target}",
        },
    }


def _evaluate(raw):
    return evaluate_rule(load_rule(RULE_PATH), normalize_gcp_audit_event(raw))


def test_true_positive_unapproved_principal_protected_target():
    finding = _evaluate(_event())

    assert finding is not None
    assert finding.rule_id == "GCP-IAM-002"
    assert finding.severity == "HIGH"
    assert finding.principal == "developer@example.com"
    assert finding.method_name == "GenerateAccessToken"
    assert finding.source_ip == "203.0.113.7"
    assert finding.timestamp == "2023-10-27T12:00:00Z"
    assert finding.mitre_attack == "T1550"
    attrs = finding.evidence["event_attributes"]
    assert attrs["target_service_account"] == PROTECTED
    assert attrs["credential_type"] == "access_token"
    assert attrs["delegation_chain"] == []
    assert finding.matched_values["attributes.target_service_account"] == [PROTECTED]
    assert finding.matched_values["principal"] == ["developer@example.com"]


def test_fp_approved_caller_does_not_trigger():
    assert _evaluate(_event(principal=ALLOWED)) is None


def test_fp_non_protected_target_does_not_trigger():
    assert _evaluate(_event(target=UNPROTECTED)) is None


def test_fp_unrelated_api_call_does_not_trigger():
    raw = {
        "timestamp": "2023-10-27T12:00:00Z",
        "protoPayload": {
            "serviceName": "storage.googleapis.com",
            "methodName": "storage.objects.get",
            "authenticationInfo": {"principalEmail": "developer@example.com"},
        },
    }
    event = normalize_gcp_audit_event(raw)

    assert event.event_type == "gcp.audit.generic"
    assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_fp_service_account_using_own_identity_does_not_trigger():
    event = normalize_gcp_audit_event(_event(principal=PROTECTED, target=PROTECTED))

    assert event.attributes["self_impersonation"] is True
    assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_missing_principal_does_not_trigger():
    raw = _event()
    del raw["protoPayload"]["authenticationInfo"]
    event = normalize_gcp_audit_event(raw)

    assert event.principal is None
    assert evaluate_rule(load_rule(RULE_PATH), event) is None


@pytest.mark.parametrize("method,credential_type", [
    ("GenerateAccessToken", "access_token"),
    ("GenerateIdToken", "id_token"),
    ("SignJwt", "signed_jwt"),
    ("SignBlob", "signed_blob"),
])
def test_credential_methods_normalize(method, credential_type):
    event = normalize_gcp_audit_event(_event(method=method))

    assert event.event_type == EVENT_TYPE
    assert event.attributes["credential_type"] == credential_type
    assert event.attributes["method_name"] == method
    assert event.attributes["service_name"] == "iamcredentials.googleapis.com"


def test_fully_qualified_method_name_is_recognized():
    method = "google.iam.credentials.v1.IAMCredentials.GenerateAccessToken"
    event = normalize_gcp_audit_event(_event(method=method))

    assert event.event_type == EVENT_TYPE
    assert event.attributes["credential_type"] == "access_token"


def test_unknown_iamcredentials_method_is_not_credential_generation():
    event = normalize_gcp_audit_event(_event(method="GetSomethingNew"))

    assert event.event_type == "gcp.audit.generic"
    assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_credential_method_from_wrong_service_is_not_credential_generation():
    raw = _event()
    raw["protoPayload"]["serviceName"] = "example.googleapis.com"

    assert normalize_gcp_audit_event(raw).event_type == "gcp.audit.generic"


def test_target_from_resource_label():
    raw = _event()
    del raw["protoPayload"]["resourceName"]

    assert normalize_gcp_audit_event(raw).attributes["target_service_account"] == PROTECTED


def test_target_from_request_name_fallback():
    raw = _event()
    del raw["resource"]
    del raw["protoPayload"]["resourceName"]
    raw["protoPayload"]["request"] = {"name": f"projects/-/serviceAccounts/{PROTECTED}"}
    event = normalize_gcp_audit_event(raw)

    assert event.attributes["target_service_account"] == PROTECTED
    assert evaluate_rule(load_rule(RULE_PATH), event) is not None


def test_label_email_preferred_over_request_name():
    raw = _event(target=PROTECTED)
    raw["protoPayload"]["request"] = {"name": f"projects/-/serviceAccounts/{UNPROTECTED}"}

    assert normalize_gcp_audit_event(raw).attributes["target_service_account"] == PROTECTED


def test_invalid_label_falls_back_to_request_name():
    raw = _event(target="not-an-email")
    raw["protoPayload"]["request"] = {"name": f"projects/-/serviceAccounts/{PROTECTED}"}

    assert normalize_gcp_audit_event(raw).attributes["target_service_account"] == PROTECTED


def test_target_email_is_case_normalized_so_case_cannot_evade_protection():
    finding = _evaluate(_event(target=PROTECTED.upper()))

    assert finding is not None
    assert finding.evidence["event_attributes"]["target_service_account"] == PROTECTED


def test_target_and_caller_are_not_confused():
    event = normalize_gcp_audit_event(_event(principal="developer@example.com", target=PROTECTED))

    assert event.principal == "developer@example.com"
    assert event.attributes["target_service_account"] == PROTECTED


def test_principal_subject_preserved():
    raw = _event()
    raw["protoPayload"]["authenticationInfo"]["principalSubject"] = "user:developer@example.com"

    assert normalize_gcp_audit_event(raw).attributes["principal_subject"] == "user:developer@example.com"


def test_delegation_chain_preserved():
    raw = _event()
    raw["protoPayload"]["authenticationInfo"]["serviceAccountDelegationInfo"] = [
        {"principalSubject": "user:original@example.com"},
        {"firstPartyPrincipal": {"principalEmail": "middle@cloudshield-lab.iam.gserviceaccount.com"}},
    ]
    finding = _evaluate(raw)

    assert finding.evidence["event_attributes"]["delegation_chain"] == [
        "user:original@example.com",
        "middle@cloudshield-lab.iam.gserviceaccount.com",
    ]


def test_missing_optional_fields_do_not_crash():
    raw = {"protoPayload": {"serviceName": "iamcredentials.googleapis.com",
                            "methodName": "GenerateAccessToken"}}
    event = normalize_gcp_audit_event(raw)

    assert event.event_type == EVENT_TYPE
    assert event.attributes["target_service_account"] is None
    assert event.attributes["source_ip"] is None
    assert event.attributes["principal_subject"] is None
    assert event.attributes["delegation_chain"] == []
    assert evaluate_rule(load_rule(RULE_PATH), event) is None


@pytest.mark.parametrize("delegation", [
    "oops", 7, {"principalSubject": "user:a@example.com"},
    [None, "x", 3, {}, {"principalSubject": 5}, {"firstPartyPrincipal": "nope"}],
])
def test_malformed_delegation_info_does_not_crash(delegation):
    raw = _event()
    raw["protoPayload"]["authenticationInfo"]["serviceAccountDelegationInfo"] = delegation

    assert normalize_gcp_audit_event(raw).attributes["delegation_chain"] == []


@pytest.mark.parametrize("resource,request_field,resource_name", [
    ("str", "str", 5),
    ({"labels": "str"}, ["a"], {"a": 1}),
    ({"labels": {"email_id": 42}}, {"name": None}, None),
    ({"labels": {"email_id": ["a@b"]}}, {"name": "projects/-/serviceAccounts/"},
     "projects/-/serviceAccounts/1234567890"),
    (None, {"name": "projects/-/serviceAccounts/a@evil.com"}, "//"),
])
def test_malformed_target_structures_do_not_crash(resource, request_field, resource_name):
    raw = _event()
    raw["resource"] = resource
    raw["protoPayload"]["request"] = request_field
    raw["protoPayload"]["resourceName"] = resource_name
    event = normalize_gcp_audit_event(raw)

    assert event.event_type == EVENT_TYPE
    assert event.attributes["target_service_account"] is None
    assert evaluate_rule(load_rule(RULE_PATH), event) is None


def test_secrets_in_request_and_response_are_not_stored():
    raw = _event()
    raw["protoPayload"]["request"] = {
        "name": f"projects/-/serviceAccounts/{PROTECTED}",
        "payload": "SECRET-PAYLOAD-TO-SIGN",
    }
    raw["protoPayload"]["response"] = {"accessToken": "ya29.SECRET-TOKEN", "signedJwt": "SECRET-JWT"}
    event = normalize_gcp_audit_event(raw)
    finding = evaluate_rule(load_rule(RULE_PATH), event)
    rendered = json.dumps([event.attributes, finding.evidence, finding.matched_values])

    assert "SECRET" not in rendered


def test_normalization_does_not_mutate_input():
    raw = _event()
    snapshot = copy.deepcopy(raw)
    normalize_gcp_audit_event(raw)

    assert raw == snapshot
