import pytest
from cloudshield.engine.rule_loader import load_rule

HEADER = """rule_id: TEST-RULE-001
title: Test rule
severity: LOW
source: gcp_audit
event_type: gcp.iam.policy_change
"""


def _write(tmp_path, conditions_yaml):
    path = tmp_path / "rule.yaml"
    path.write_text(HEADER + conditions_yaml, encoding="utf-8")
    return str(path)


def test_unsupported_operator_fails_at_load_time(tmp_path):
    path = _write(tmp_path, """conditions:
  - field: attributes.roles_added
    operator: contains_regex
    value: ["roles/.*"]
""")
    with pytest.raises(ValueError) as exc:
        load_rule(path)

    message = str(exc.value)
    assert "TEST-RULE-001" in message
    assert "attributes.roles_added" in message
    assert 'unsupported operator "contains_regex"' in message


def test_empty_operator_fails_at_load_time(tmp_path):
    path = _write(tmp_path, """conditions:
  - field: attributes.roles_added
    operator: {}
    value: ["roles/owner"]
""")
    with pytest.raises(ValueError, match="unsupported operator"):
        load_rule(path)


def test_empty_condition_mapping_fails_at_load_time(tmp_path):
    with pytest.raises(ValueError, match="TEST-RULE-001"):
        load_rule(_write(tmp_path, "conditions:\n  - {}\n"))


@pytest.mark.parametrize("conditions_yaml", [
    # several operators in a single condition
    """conditions:
  - field: attributes.roles_added
    operator: contains_any
    contains_all: ["roles/owner"]
    value: ["roles/owner"]
""",
    # operator that is a list of operators
    """conditions:
  - field: attributes.roles_added
    operator: [contains_any, contains_all]
    value: ["roles/owner"]
""",
    # condition is not a mapping
    "conditions:\n  - just-a-string\n",
    # missing field
    """conditions:
  - operator: equals
    value: x
""",
    # missing value
    """conditions:
  - field: attributes.roles_added
    operator: equals
""",
    # contains_any with scalar value
    """conditions:
  - field: attributes.roles_added
    operator: contains_any
    value: roles/owner
""",
    # contains_any with empty list would never match
    """conditions:
  - field: attributes.roles_added
    operator: contains_any
    value: []
""",
])
def test_malformed_conditions_fail_at_load_time(tmp_path, conditions_yaml):
    with pytest.raises(ValueError):
        load_rule(_write(tmp_path, conditions_yaml))


def test_valid_supported_operators_load(tmp_path):
    path = _write(tmp_path, """conditions:
  - field: attributes.roles_added
    operator: contains_any
    value: ["roles/owner"]
  - field: attributes.roles_added
    operator: contains_all
    value: ["roles/owner"]
  - field: principal
    operator: equals
    value: someone@example.com
""")
    assert len(load_rule(path).conditions) == 3
