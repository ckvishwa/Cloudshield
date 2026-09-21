"""Bind a portable rule to environment-specific values at runtime.

Committed rules carry safe example values (for instance the project name
``cloudshield-lab`` in service account emails). These helpers return a NEW rule
with real values injected, so no private identifiers are committed and the
loaded rule is never mutated.
"""
import copy
from typing import Any, List, Sequence

from cloudshield.config import validate_project_id
from cloudshield.engine.rule_loader import validate_conditions
from cloudshield.models import DetectionRule

SERVICE_ACCOUNT_IMPERSONATION_RULE_ID = "GCP-IAM-002"
TARGET_FIELD = "attributes.target_service_account"
CALLER_FIELD = "principal"


def override_condition_value(
    rule: DetectionRule, field: str, operator: str, value: Any
) -> DetectionRule:
    """Copy of rule whose (field, operator) condition carries a new value.

    Exactly one condition must match, so a typo cannot turn into a silent no-op.
    The replacement is validated with the same checks as load_rule().
    """
    updated = copy.deepcopy(rule)
    matches = [
        c for c in updated.conditions
        if isinstance(c, dict) and c.get("field") == field and c.get("operator") == operator
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Rule {rule.rule_id}: expected exactly one condition for field {field!r} "
            f"with operator {operator!r}, found {len(matches)}"
        )
    matches[0]["value"] = copy.deepcopy(value)
    validate_conditions(updated.rule_id, updated.conditions)
    return updated


def _service_account_emails(project_id: str, account_ids: Sequence[str]) -> List[str]:
    return [f"{account_id}@{project_id}.iam.gserviceaccount.com" for account_id in account_ids]


def bind_service_account_impersonation_rule(
    rule: DetectionRule,
    project_id: str,
    protected_accounts: Sequence[str] = ("prod-admin",),
    approved_callers: Sequence[str] = ("ci-deployer",),
) -> DetectionRule:
    """Bind GCP-IAM-002 to service accounts of a real project.

    protected_accounts / approved_callers are service account IDs (the part
    before the @); they are expanded to <id>@<project_id>.iam.gserviceaccount.com.
    """
    if rule.rule_id != SERVICE_ACCOUNT_IMPERSONATION_RULE_ID:
        raise ValueError(
            f"Expected rule {SERVICE_ACCOUNT_IMPERSONATION_RULE_ID}, got {rule.rule_id}"
        )
    validate_project_id(project_id)
    bound = override_condition_value(
        rule, TARGET_FIELD, "in", _service_account_emails(project_id, protected_accounts)
    )
    return override_condition_value(
        bound, CALLER_FIELD, "not_in", _service_account_emails(project_id, approved_callers)
    )
