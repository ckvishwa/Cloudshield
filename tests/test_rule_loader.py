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


@pytest.mark.parametrize("operator", ["in", "not_in"])
def test_membership_operators_load_with_list_value(tmp_path, operator):
    path = _write(tmp_path, f"conditions:\n  - field: principal\n    operator: {operator}\n    value: [a@example.com]\n")

    assert load_rule(path).conditions[0]["operator"] == operator


@pytest.mark.parametrize("operator", ["in", "not_in"])
@pytest.mark.parametrize("value_yaml", ["a@example.com", "[]"])
def test_membership_operators_reject_scalar_or_empty_value(tmp_path, operator, value_yaml):
    path = _write(tmp_path, f"conditions:\n  - field: principal\n    operator: {operator}\n    value: {value_yaml}\n")

    with pytest.raises(ValueError, match="non-empty list"):
        load_rule(path)


def test_shipped_iam_rules_load():
    import glob
    import os
    pattern = os.path.join(os.path.dirname(__file__), "..", "rules", "iam", "*.yaml")
    ids = {load_rule(p).rule_id for p in glob.glob(pattern)}

    assert {"GCP-IAM-001", "GCP-IAM-002"} <= ids


# ---- load_rules(): directory discovery --------------------------------------

from pathlib import Path

from cloudshield.engine.rule_loader import load_rules

REPO_RULES = Path(__file__).resolve().parent.parent / "rules"


def _rule_yaml(rule_id, event_type="gcp.iam.policy_change"):
    return (
        f"rule_id: {rule_id}\ntitle: t\nseverity: LOW\nsource: gcp_audit\n"
        f"event_type: {event_type}\nconditions:\n"
        "  - field: principal\n    operator: equals\n    value: x\n"
    )


def _put(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_load_rules_repository_rules_directory_strict():
    rules = load_rules(REPO_RULES)

    assert [r.rule_id for r in rules] == ["GCP-IAM-001", "GCP-IAM-002"]


def test_repository_has_no_empty_rule_files():
    empty = [
        str(p) for p in REPO_RULES.rglob("*")
        if p.is_file() and p.suffix.lower() in (".yaml", ".yml") and not p.read_text(encoding="utf-8").strip()
    ]

    assert empty == []


@pytest.mark.parametrize("content", ["", "   ", "# only a comment"])
def test_load_rules_empty_yaml_file_fails(tmp_path, content):
    _put(tmp_path, "ok.yaml", _rule_yaml("R-1"))
    empty = _put(tmp_path, "empty.yaml", content)

    with pytest.raises(ValueError, match="Failed to load rule file") as exc:
        load_rules(tmp_path)

    assert str(empty) in str(exc.value)


def test_load_rules_order_is_deterministic_by_relative_path(tmp_path):
    _put(tmp_path, "network/a.yaml", _rule_yaml("NET-A"))
    _put(tmp_path, "iam/b.yml", _rule_yaml("IAM-B"))
    _put(tmp_path, "iam/a.yaml", _rule_yaml("IAM-A"))
    _put(tmp_path, "iam/nested/z.yaml", _rule_yaml("IAM-Z"))

    first = [r.rule_id for r in load_rules(tmp_path)]

    assert first == ["IAM-A", "IAM-B", "IAM-Z", "NET-A"]
    assert [r.rule_id for r in load_rules(tmp_path)] == first


def test_load_rules_discovers_nested_directories(tmp_path):
    _put(tmp_path, "a/b/c/deep.yaml", _rule_yaml("DEEP-1"))

    assert [r.rule_id for r in load_rules(tmp_path)] == ["DEEP-1"]


def test_load_rules_ignores_non_yaml_files(tmp_path):
    _put(tmp_path, "rule.yaml", _rule_yaml("R-1"))
    _put(tmp_path, "notes.md", "not a rule")
    _put(tmp_path, "rule.yaml.bak", "garbage: [")
    _put(tmp_path, "data.json", "{}")

    assert [r.rule_id for r in load_rules(tmp_path)] == ["R-1"]


def test_load_rules_empty_directory_returns_empty_list(tmp_path):
    assert load_rules(tmp_path) == []


def test_load_rules_missing_directory_raises(tmp_path):
    with pytest.raises(ValueError, match="not a directory"):
        load_rules(tmp_path / "does-not-exist")


def test_load_rules_duplicate_ids_raise_naming_both_files(tmp_path):
    first = _put(tmp_path, "iam/one.yaml", _rule_yaml("GCP-IAM-001"))
    second = _put(tmp_path, "iam/two.yaml", _rule_yaml("GCP-IAM-001", "gcp.other"))

    with pytest.raises(ValueError) as exc:
        load_rules(tmp_path)

    message = str(exc.value)
    assert "Duplicate rule_id" in message and "GCP-IAM-001" in message
    assert str(first) in message and str(second) in message


def test_load_rules_duplicate_ids_differing_only_by_case_raise(tmp_path):
    _put(tmp_path, "a.yaml", _rule_yaml("GCP-IAM-001"))
    _put(tmp_path, "b.yaml", _rule_yaml("gcp-iam-001"))

    with pytest.raises(ValueError, match="Duplicate rule_id"):
        load_rules(tmp_path)


@pytest.mark.parametrize("bad_text", [
    "rule_id: [unclosed",                        # invalid YAML
    "- just\n- a list\n",                        # not a mapping
    "rule_id: X\ntitle: t\n",                    # missing required fields
    _rule_yaml("X").replace("equals", "regex"),  # unsupported operator
    _rule_yaml("[a, b]"),                        # non-string rule_id
])
def test_load_rules_invalid_rule_fails_and_names_file(tmp_path, bad_text):
    _put(tmp_path, "good.yaml", _rule_yaml("GOOD-1"))
    bad = _put(tmp_path, "zbad.yaml", bad_text)

    with pytest.raises(ValueError, match="Failed to load rule file") as exc:
        load_rules(tmp_path)

    assert str(bad) in str(exc.value)
