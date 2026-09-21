"""Score detections against labeled events and run a labeled replay.

Scoring is multi-label and set-based per event: each (event, rule) pair is a
true positive (expected and fired), false positive (fired, not expected) or
false negative (expected, did not fire). The numbers describe one corpus only;
they are not production accuracy metrics.
"""
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Sequence

from cloudshield.dataset import DatasetEvent
from cloudshield.engine.runner import run_event
from cloudshield.models import DetectionRule
from cloudshield.replay import DEFAULT_MAX_SLEEP_SECONDS, MODE_INSTANT, replay
from cloudshield.telemetry.registry import TelemetryAdapter, get_adapter

_ROUND = 6


@dataclass(frozen=True)
class EventOutcome:
    event_id: str
    expected: FrozenSet[str]
    actual: FrozenSet[str]
    finding_count: int = 0


@dataclass(frozen=True)
class RuleScore:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: Optional[float]
    recall: Optional[float]
    f1: Optional[float]


@dataclass(frozen=True)
class EvaluationReport:
    events: int
    findings: int
    expected_detections: int
    actual_detections: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int  # (event, rule) pairs neither expected nor fired
    precision: Optional[float]
    recall: Optional[float]
    f1: Optional[float]
    rules: Dict[str, RuleScore]
    mismatches: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events": self.events,
            "findings": self.findings,
            "expected_detections": self.expected_detections,
            "actual_detections": self.actual_detections,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "rules": {rule_id: vars(score).copy() for rule_id, score in self.rules.items()},
            "mismatches": self.mismatches,
        }


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, _ROUND) if denominator else None


def _f1(precision: Optional[float], recall: Optional[float]) -> Optional[float]:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return round(2 * precision * recall / (precision + recall), _ROUND)


def _rule_score(tp: int, fp: int, fn: int) -> RuleScore:
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    return RuleScore(tp, fp, fn, precision, recall, _f1(precision, recall))


def score_outcomes(outcomes: Sequence[EventOutcome], rule_ids: Iterable[str] = ()) -> EvaluationReport:
    """Aggregate per-event outcomes into overall and per-rule metrics.

    rule_ids is the universe of rules under evaluation (used for true negatives
    and so rules with no activity still appear); any rule seen in a label or a
    finding is added automatically.
    """
    universe = set(rule_ids)
    for outcome in outcomes:
        universe |= outcome.expected | outcome.actual

    tp: Dict[str, int] = {r: 0 for r in universe}
    fp: Dict[str, int] = {r: 0 for r in universe}
    fn: Dict[str, int] = {r: 0 for r in universe}
    mismatches: List[Dict[str, Any]] = []
    for outcome in outcomes:
        for rule_id in outcome.expected & outcome.actual:
            tp[rule_id] += 1
        false_pos = outcome.actual - outcome.expected
        false_neg = outcome.expected - outcome.actual
        for rule_id in false_pos:
            fp[rule_id] += 1
        for rule_id in false_neg:
            fn[rule_id] += 1
        if false_pos or false_neg:
            mismatches.append({
                "event_id": outcome.event_id,
                "false_positives": sorted(false_pos),
                "false_negatives": sorted(false_neg),
            })

    total_tp, total_fp, total_fn = sum(tp.values()), sum(fp.values()), sum(fn.values())
    precision, recall = _ratio(total_tp, total_tp + total_fp), _ratio(total_tp, total_tp + total_fn)
    return EvaluationReport(
        events=len(outcomes),
        findings=sum(o.finding_count for o in outcomes),
        expected_detections=sum(len(o.expected) for o in outcomes),
        actual_detections=sum(len(o.actual) for o in outcomes),
        true_positives=total_tp,
        false_positives=total_fp,
        false_negatives=total_fn,
        true_negatives=len(outcomes) * len(universe) - total_tp - total_fp - total_fn,
        precision=precision,
        recall=recall,
        f1=_f1(precision, recall),
        rules={r: _rule_score(tp[r], fp[r], fn[r]) for r in sorted(universe)},
        mismatches=mismatches,
    )


def evaluate_dataset(
    events: Sequence[DatasetEvent],
    rules: Sequence[DetectionRule],
    *,
    mode: str = MODE_INSTANT,
    speed: float = 1.0,
    max_sleep_seconds: float = DEFAULT_MAX_SLEEP_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    adapter: Optional[TelemetryAdapter] = None,
    score_rules: Optional[Sequence[str]] = None,
) -> EvaluationReport:
    """Replay events in order through normalize -> run_event and score the result.

    Only ``event.raw`` reaches the normalizer; labels stay out of the pipeline.
    ``adapter`` selects the telemetry normalizer (default: gcp_audit). Every rule
    is executed; ``score_rules`` is the rule universe for scoring (default: all
    rules), and any other rule that fires is still scored, as a false positive.
    """
    adapter = adapter or get_adapter("gcp_audit")
    outcomes: List[EventOutcome] = []
    for event in replay(events, lambda e: adapter.timestamp_of(e.raw), mode, speed,
                        max_sleep_seconds=max_sleep_seconds, sleep=sleep):
        findings = run_event(adapter.normalize(event.raw), rules)
        outcomes.append(EventOutcome(
            event_id=event.event_id,
            expected=frozenset(event.expected_rules),
            actual=frozenset(f.rule_id for f in findings),
            finding_count=len(findings),
        ))
    return score_outcomes(outcomes, score_rules if score_rules is not None else [rule.rule_id for rule in rules])
