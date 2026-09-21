import copy
import os

import pytest

from cloudshield.engine.evaluator import evaluate_rule
from cloudshield.engine.rule_binding import (
    bind_service_account_impersonation_rule,
    override_condition_value,
)
from cloudshield.engine.rule_loader import load_rule
from cloudshield.telemetry.gcp_audit import normalize_gcp_audit_event

RULE_DIR = os.path.join(os.path.dirname(__file__), "..", "rules", "iam")
PROJECT = "my-lab-project-1"
PROTECTED = f"prod-admin@{PROJECT}.iam.gserviceaccount.com"
APPROVED = f"ci-deployer@{PROJECT}.iam.gserviceaccount.com"


def _rule():
    return load_rule(os.path.join(RULE_DIR, "service_account_impersonation.yaml"))


def _event(principal="developer@example.com", target=PROTECTED):
    return normalize_gcp_audit_event({
        "timestamp": "2023-10-27T12:00:00Z",
        "resource": {"labels": {"email_id": target}},
        "protoPayload": {
            "serviceName": "iamcredentials.googleapis.com",
            "methodName": "GenerateAccessToken",
            "authenticationInfo": {"principalEmail": principal},
        },
    })


def test_binding_does_not_mutate_original_rule():
    original = _rule()
    snapshot = copy.deepcopy(original)

    bound = bind_service_account_impersonation_rule(original, PROJECT)

    assert original == snapshot
    assert bound is not original
    assert bound.conditions is not original.conditions


def test_bound_rule_matches_project_specific_protected_account():
    finding = evaluate_rule(bind_service_account_impersonation_rule(_rule(), PROJECT), _event())

    assert finding is not None
    assert finding.evidence["event_attributes"]["target_service_account"] == PROTECTED


def test_bound_rule_ignores_wrong_target():
    bound = bind_service_account_impersonation_rule(_rule(), PROJECT)

    assert evaluate_rule(bound, _event(target=f"dev-worker@{PROJECT}.iam.gserviceaccount.com")) is None
    # the committed example project's account is no longer protected once bound
    assert evaluate_rule(bound, _event(target="prod-admin@cloudshield-lab.iam.gserviceaccount.com")) is None


def test_bound_rule_uses_project_specific_approved_caller():
    bound = bind_service_account_impersonation_rule(_rule(), PROJECT)

    assert evaluate_rule(bound, _event(principal=APPROVED)) is None
    assert evaluate_rule(
        bound, _event(principal="ci-deployer@cloudshield-lab.iam.gserviceaccount.com")
    ) is not None


def test_committed_rule_keeps_example_values():
    values = {c["field"]: c["value"] for c in _rule().conditions}

    assert values["attributes.target_service_account"][0].endswith("@cloudshield-lab.iam.gserviceaccount.com")


def test_custom_account_lists():
    bound = bind_service_account_impersonation_rule(
        _rule(), PROJECT, protected_accounts=["a-one", "a-two"], approved_callers=["ci-x"])
    values = {c["field"]: c["value"] for c in bound.conditions}

    assert values["attributes.target_service_account"] == [
        f"a-one@{PROJECT}.iam.gserviceaccount.com", f"a-two@{PROJECT}.iam.gserviceaccount.com"]
    assert values["principal"] == [f"ci-x@{PROJECT}.iam.gserviceaccount.com"]


def test_binding_rejects_other_rules_and_bad_project():
    iam_001 = load_rule(os.path.join(RULE_DIR, "privilege_escalation.yaml"))

    with pytest.raises(ValueError, match="Expected rule GCP-IAM-002"):
        bind_service_account_impersonation_rule(iam_001, PROJECT)
    with pytest.raises(ValueError, match="Invalid GCP project ID"):
        bind_service_account_impersonation_rule(_rule(), 'x@evil" OR "1')


def test_binding_rejects_empty_lists():
    with pytest.raises(ValueError, match="non-empty list"):
        bind_service_account_impersonation_rule(_rule(), PROJECT, protected_accounts=[])


def test_override_requires_exactly_one_matching_condition():
    rule = _rule()

    with pytest.raises(ValueError, match="found 0"):
        override_condition_value(rule, "principal", "in", ["x"])
    with pytest.raises(ValueError, match="found 0"):
        override_condition_value(rule, "no.such.field", "not_in", ["x"])
