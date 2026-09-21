import pytest

from cloudshield.dataset import DatasetEvent
from cloudshield.evaluation import (
    EventOutcome,
    evaluate_dataset,
    score_outcomes,
)
from cloudshield.models import DetectionRule


def _o(event_id, expected=(), actual=(), findings=None):
    actual = frozenset(actual)
    return EventOutcome(event_id, frozenset(expected), actual, len(actual) if findings is None else findings)


def test_true_positive():
    report = score_outcomes([_o("e1", ["R1"], ["R1"])], ["R1"])

    assert (report.true_positives, report.false_positives, report.false_negatives) == (1, 0, 0)
    assert report.mismatches == []


def test_false_positive():
    report = score_outcomes([_o("e1", [], ["R1"])], ["R1"])

    assert (report.true_positives, report.false_positives, report.false_negatives) == (0, 1, 0)
    assert report.mismatches == [{"event_id": "e1", "false_positives": ["R1"], "false_negatives": []}]


def test_false_negative():
    report = score_outcomes([_o("e1", ["R1"], [])], ["R1"])

    assert (report.true_positives, report.false_positives, report.false_negatives) == (0, 0, 1)
    assert report.mismatches == [{"event_id": "e1", "false_positives": [], "false_negatives": ["R1"]}]


def test_multi_label_event_is_scored_per_rule_not_as_a_boolean():
    report = score_outcomes([_o("e1", ["GCP-IAM-001", "RULE-X"], ["GCP-IAM-001", "RULE-Y"])])

    assert report.rules["GCP-IAM-001"].true_positives == 1
    assert report.rules["RULE-X"].false_negatives == 1
    assert report.rules["RULE-Y"].false_positives == 1
    assert (report.true_positives, report.false_positives, report.false_negatives) == (1, 1, 1)
    assert report.expected_detections == 2 and report.actual_detections == 2


def test_precision_recall_f1_values():
    outcomes = [
        _o("a", ["R"], ["R"]), _o("b", ["R"], ["R"]), _o("c", ["R"], ["R"]),  # 3 TP
        _o("d", [], ["R"]),                                                     # 1 FP
        _o("e", ["R"], []), _o("f", ["R"], []),                                 # 2 FN
        _o("g", [], []),                                                        # TN
    ]
    report = score_outcomes(outcomes, ["R"])

    assert report.precision == 0.75           # 3 / (3 + 1)
    assert report.recall == 0.6               # 3 / (3 + 2)
    assert report.f1 == pytest.approx(2 * 0.75 * 0.6 / (0.75 + 0.6), abs=1e-6)
    assert report.true_negatives == 1
    assert report.rules["R"].precision == 0.75


def test_zero_denominators_give_none_not_errors():
    empty = score_outcomes([], [])
    assert (empty.events, empty.precision, empty.recall, empty.f1) == (0, None, None, None)

    all_benign = score_outcomes([_o("a"), _o("b")], ["R"])
    assert (all_benign.precision, all_benign.recall, all_benign.f1) == (None, None, None)
    assert all_benign.true_negatives == 2

    only_fp = score_outcomes([_o("a", [], ["R"])], ["R"])
    assert (only_fp.precision, only_fp.recall, only_fp.f1) == (0.0, None, None)

    only_fn = score_outcomes([_o("a", ["R"], [])], ["R"])
    assert (only_fn.precision, only_fn.recall, only_fn.f1) == (None, 0.0, None)


def test_per_rule_results_include_idle_rules_and_are_sorted():
    report = score_outcomes([_o("a", ["B"], ["B"])], ["C", "A", "B"])

    assert list(report.rules) == ["A", "B", "C"]
    assert report.rules["A"].true_positives == 0 and report.rules["A"].precision is None
    assert report.rules["B"].f1 == 1.0


def test_true_negatives_count_event_rule_pairs():
    report = score_outcomes([_o("a", ["R1"], ["R1"]), _o("b"), _o("c")], ["R1", "R2"])

    assert report.true_negatives == 3 * 2 - 1


def test_findings_count_is_separate_from_detection_sets():
    report = score_outcomes([_o("a", ["R"], ["R"], findings=3)], ["R"])

    assert report.findings == 3 and report.actual_detections == 1


def test_report_dict_is_json_ready_and_stable():
    import json
    report = score_outcomes([_o("a", ["R"], ["R"])], ["R"])
    as_dict = report.to_dict()

    assert json.loads(json.dumps(as_dict)) == as_dict
    assert as_dict["rules"]["R"]["true_positives"] == 1


# ---- evaluate_dataset wiring ---------------------------------------------------

def _rule():
    return DetectionRule(
        rule_id="SYN-1", title="t", severity="LOW", source="gcp_audit",
        event_type="gcp.iam.policy_change",
        conditions=[{"field": "attributes.roles_added", "operator": "contains_any", "value": ["roles/owner"]}])


def _dataset_event(event_id, role, expected, timestamp):
    raw = {"timestamp": timestamp, "protoPayload": {"metadata": {"bindingDeltas": [
        {"action": "ADD", "role": role, "member": "user:a@example.com"}]}}}
    return DatasetEvent(event_id, "synthetic_variant", "ref", "parent", tuple(expected), raw)


def test_evaluate_dataset_scores_labels_against_real_detections():
    events = [
        _dataset_event("hit", "roles/owner", ["SYN-1"], "2024-08-05T10:00:00Z"),
        _dataset_event("miss-label", "roles/owner", [], "2024-08-05T10:00:10Z"),
        _dataset_event("benign", "roles/viewer", [], "2024-08-05T10:00:20Z"),
        _dataset_event("missed", "roles/viewer", ["SYN-1"], "2024-08-05T10:00:30Z"),
    ]
    report = evaluate_dataset(events, [_rule()])

    assert (report.events, report.true_positives, report.false_positives, report.false_negatives) == (4, 1, 1, 1)
    assert {m["event_id"] for m in report.mismatches} == {"miss-label", "missed"}


def test_evaluate_dataset_instant_mode_does_not_sleep_and_accelerated_does():
    events = [_dataset_event("a", "roles/owner", ["SYN-1"], "2024-08-05T10:00:00Z"),
              _dataset_event("b", "roles/owner", ["SYN-1"], "2024-08-05T10:00:20Z")]
    sleeps = []

    evaluate_dataset(events, [_rule()], sleep=sleeps.append)
    assert sleeps == []
    evaluate_dataset(events, [_rule()], mode="accelerated", speed=10, sleep=sleeps.append)
    assert sleeps == [2.0]


def test_evaluate_dataset_passes_only_raw_to_the_pipeline():
    seen = []
    event = _dataset_event("a", "roles/owner", ["SYN-1"], "2024-08-05T10:00:00Z")
    report = evaluate_dataset([event], [_rule()])

    assert report.true_positives == 1
    assert "expected_rules" not in event.raw and "event_id" not in event.raw
    assert not seen
