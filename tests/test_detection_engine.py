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
