"""Regression tests: raw payload values and unredacted identifiers must not leak."""
import pytest

from cloudshield.engine.evaluator import evaluate_rule
from cloudshield.engine.rule_loader import validate_conditions
from cloudshield.models import DetectionRule, NormalizedEvent
from cloudshield.telemetry.gcp_logging import redact_audit_dict


def _event_with_raw_token() -> NormalizedEvent:
    return NormalizedEvent(
        source="gcp_audit", event_type="gcp.audit.generic", timestamp=None, principal=None,
        resource=None, attributes={},
        raw={"protoPayload": {"response": {"accessToken": "SECRET-TOKEN"}}},
    )


def _raw_field_rule() -> DetectionRule:
    return DetectionRule(
        rule_id="R-1", title="t", severity="high", source="gcp_audit",
        event_type="gcp.audit.generic",
        conditions=[{"field": "raw.protoPayload.response.accessToken", "operator": "not_in",
                     "value": ["x"]}],
    )


def test_rule_cannot_copy_raw_payload_values_into_a_finding():
    with pytest.raises(ValueError, match="raw"):
        evaluate_rule(_raw_field_rule(), _event_with_raw_token())


def test_rule_loader_rejects_conditions_on_raw_event_fields():
    with pytest.raises(ValueError, match="raw"):
        validate_conditions("R-1", _raw_field_rule().conditions)


@pytest.mark.parametrize("field", ["principal", "resource", "attributes.roles_added",
                                   "attributes.target_service_account"])
def test_rule_loader_still_accepts_normalized_fields(field):
    validate_conditions("R-1", [{"field": field, "operator": "equals", "value": "x"}])


@pytest.mark.parametrize("secret", ["josé@corp.example", 'quote"inside', "back\\slash", "emoji-\U0001f511"])
def test_redaction_replaces_values_json_would_escape(secret):
    raw = {"protoPayload": {"authenticationInfo": {"principalEmail": secret}}, "note": f"by {secret}"}
    redacted = redact_audit_dict(raw, {secret: "REDACTED"})
    assert secret not in repr(redacted)
    assert redacted["protoPayload"]["authenticationInfo"]["principalEmail"] == "REDACTED"
    assert redacted["note"] == "by REDACTED"


def test_redaction_replaces_values_in_keys():
    redacted = redact_audit_dict({"labels": {"corp-project-1": "v"}}, {"corp-project-1": "lab"})
    assert redacted == {"labels": {"lab": "v"}}


def test_redaction_does_not_mutate_input():
    raw = {"a": "secret"}
    redact_audit_dict(raw, {"secret": "X"})
    assert raw == {"a": "secret"}
