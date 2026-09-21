import pytest

from cloudshield.engine.evaluator import evaluate_rule
from cloudshield.models import DetectionRule, NormalizedEvent


def _rule(operator, value, field="principal"):
    return DetectionRule(
        rule_id="TEST-OP",
        title="operator test",
        severity="LOW",
        source="gcp_audit",
        event_type="t",
        conditions=[{"field": field, "operator": operator, "value": value}],
    )


def _event(principal="a@example.com", **attributes):
    return NormalizedEvent(
        source="gcp_audit", event_type="t", timestamp=None,
        principal=principal, resource=None, attributes=attributes,
    )


def test_not_in_matches_value_outside_list():
    finding = evaluate_rule(_rule("not_in", ["b@example.com"]), _event())

    assert finding is not None
    assert finding.matched_values == {"principal": ["a@example.com"]}


def test_not_in_does_not_match_value_inside_list():
    assert evaluate_rule(_rule("not_in", ["a@example.com", "b@example.com"]), _event()) is None


def test_not_in_does_not_match_missing_value():
    assert evaluate_rule(_rule("not_in", ["b@example.com"]), _event(principal=None)) is None
    assert evaluate_rule(_rule("not_in", ["b@example.com"], field="attributes.absent"), _event()) is None


def test_not_in_does_not_match_non_scalar_value():
    event = _event(roles=["x"])

    assert evaluate_rule(_rule("not_in", ["y"], field="attributes.roles"), event) is None


def test_in_matches_value_inside_list_only():
    assert evaluate_rule(_rule("in", ["a@example.com"]), _event()) is not None
    assert evaluate_rule(_rule("in", ["b@example.com"]), _event()) is None
    assert evaluate_rule(_rule("in", ["b@example.com"]), _event(principal=None)) is None


def test_in_does_not_match_list_valued_field():
    event = _event(roles=["a@example.com"])

    assert evaluate_rule(_rule("in", ["a@example.com"], field="attributes.roles"), event) is None


def test_in_and_not_in_require_list_rule_value():
    for operator in ("in", "not_in"):
        with pytest.raises(ValueError, match="requires a list"):
            evaluate_rule(_rule(operator, "a@example.com"), _event())


def test_equals_supports_false_value():
    rule = _rule("equals", False, field="attributes.flag")

    assert evaluate_rule(rule, _event(flag=False)) is not None
    assert evaluate_rule(rule, _event(flag=True)) is None


# ---- runner: run_event / run_events -----------------------------------------

import copy
from pathlib import Path

from cloudshield.engine.rule_loader import load_rules
from cloudshield.engine.runner import run_event, run_events
from cloudshield.telemetry.gcp_audit import normalize_gcp_audit_event

REPO_RULES = Path(__file__).resolve().parent.parent / "rules"
PROTECTED = "prod-admin@cloudshield-lab.iam.gserviceaccount.com"


@pytest.fixture(scope="module")
def repo_rules():
    # skip_empty: the scaffold still has zero-byte placeholder rule files
    return load_rules(REPO_RULES, skip_empty=True)


def _iam_policy_event(role):
    return normalize_gcp_audit_event({
        "timestamp": "2023-10-27T12:00:00Z",
        "protoPayload": {
            "authenticationInfo": {"principalEmail": "admin@example.com"},
            "resourceName": "projects/cloudshield-lab",
            "methodName": "SetIamPolicy",
            "metadata": {"bindingDeltas": [
                {"action": "ADD", "role": role, "member": "user:b@example.com"}
            ]},
        },
    })


def _token_event(principal="developer@example.com", target=PROTECTED):
    return normalize_gcp_audit_event({
        "timestamp": "2023-10-27T12:05:00Z",
        "resource": {"labels": {"email_id": target}},
        "protoPayload": {
            "serviceName": "iamcredentials.googleapis.com",
            "methodName": "GenerateAccessToken",
            "authenticationInfo": {"principalEmail": principal},
        },
    })


def _unrelated_event():
    return normalize_gcp_audit_event({
        "protoPayload": {
            "serviceName": "storage.googleapis.com",
            "methodName": "storage.objects.get",
            "authenticationInfo": {"principalEmail": "developer@example.com"},
        },
    })


def _synthetic_rule(rule_id, conditions=None):
    return DetectionRule(
        rule_id=rule_id, title=rule_id, severity="LOW",
        source="gcp_audit", event_type="t",
        conditions=conditions or [{"field": "principal", "operator": "equals", "value": "a@example.com"}],
    )


def _ids(findings):
    return [f.rule_id for f in findings]


def test_run_event_iam_policy_event_fires_only_iam_001(repo_rules):
    assert _ids(run_event(_iam_policy_event("roles/owner"), repo_rules)) == ["GCP-IAM-001"]


def test_run_event_token_event_fires_only_iam_002(repo_rules):
    assert _ids(run_event(_token_event(), repo_rules)) == ["GCP-IAM-002"]


def test_run_event_benign_policy_event_returns_empty(repo_rules):
    assert run_event(_iam_policy_event("roles/viewer"), repo_rules) == []


def test_run_event_unrelated_event_returns_empty(repo_rules):
    assert run_event(_unrelated_event(), repo_rules) == []


def test_run_event_with_no_rules_returns_empty():
    assert run_event(_iam_policy_event("roles/owner"), []) == []


def test_run_event_one_event_can_produce_multiple_findings_in_rule_order():
    rules = [
        _synthetic_rule("SYN-B"),
        _synthetic_rule("SYN-A", [{"field": "principal", "operator": "in", "value": ["a@example.com"]}]),
        _synthetic_rule("SYN-NO", [{"field": "principal", "operator": "equals", "value": "other"}]),
    ]

    assert _ids(run_event(_event(), rules)) == ["SYN-B", "SYN-A"]


def test_run_events_multiple_events_ordered_by_event_then_rule(repo_rules):
    events = [_iam_policy_event("roles/owner"), _iam_policy_event("roles/viewer"), _token_event()]

    assert _ids(run_events(events, repo_rules)) == ["GCP-IAM-001", "GCP-IAM-002"]


def test_run_events_accepts_one_shot_iterators(repo_rules):
    events = iter([_token_event(), _iam_policy_event("roles/owner"), _token_event()])

    assert _ids(run_events(events, iter(repo_rules))) == ["GCP-IAM-002", "GCP-IAM-001", "GCP-IAM-002"]


def test_run_events_with_no_events_returns_empty(repo_rules):
    assert run_events([], repo_rules) == []


def test_runner_propagates_evaluator_errors_instead_of_partial_results():
    bad = _synthetic_rule("SYN-BAD", [{"field": "principal", "operator": "regex", "value": "x"}])
    good = _synthetic_rule("SYN-GOOD")

    with pytest.raises(ValueError, match="Unknown operator"):
        run_event(_event(), [good, bad])
    with pytest.raises(ValueError, match="Unknown operator"):
        run_events([_event()], [good, bad])


def test_runner_propagates_unexpected_evaluator_failures(monkeypatch):
    import cloudshield.engine.runner as runner_module

    def boom(rule, event):
        raise RuntimeError("evaluator bug")

    monkeypatch.setattr(runner_module, "evaluate_rule", boom)

    with pytest.raises(RuntimeError, match="evaluator bug"):
        run_event(_event(), [_synthetic_rule("SYN-1")])


def test_runner_does_not_mutate_events_or_rules(repo_rules):
    events = [_iam_policy_event("roles/owner"), _token_event(), _unrelated_event()]
    events_before = copy.deepcopy(events)
    rules_before = copy.deepcopy(repo_rules)

    findings = run_events(events, repo_rules)

    assert len(findings) == 2
    assert events == events_before
    assert repo_rules == rules_before


def test_findings_do_not_alias_event_or_rule_data(repo_rules):
    event = _iam_policy_event("roles/owner")
    event_before = copy.deepcopy(event)
    rules_before = copy.deepcopy(repo_rules)

    (finding,) = run_event(event, repo_rules)
    finding.evidence["event_attributes"]["roles_added"].append("tampered")
    finding.evidence["matched_conditions"][0]["value"].append("tampered")
    finding.evidence["matched_bindings"][0]["role"] = "tampered"
    finding.matched_values["attributes.roles_added"].append("tampered")

    assert event == event_before
    assert repo_rules == rules_before
