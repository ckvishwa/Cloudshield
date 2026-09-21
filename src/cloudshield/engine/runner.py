from typing import Iterable, List, Sequence

from cloudshield.engine.evaluator import evaluate_rule
from cloudshield.models import DetectionRule, Finding, NormalizedEvent


def run_event(event: NormalizedEvent, rules: Sequence[DetectionRule]) -> List[Finding]:
    """Evaluate one event against every rule, in the order the rules are given.

    Returns 0..N findings; a match never short-circuits later rules. Errors from
    evaluate_rule() propagate on purpose: a partial result must never look like
    a complete one. Cost is O(rules) per event (no rule indexing yet).
    """
    findings: List[Finding] = []
    for rule in rules:
        finding = evaluate_rule(rule, event)
        if finding is not None:
            findings.append(finding)
    return findings


def run_events(events: Iterable[NormalizedEvent], rules: Sequence[DetectionRule]) -> List[Finding]:
    """Run events in input order; findings are ordered by event, then by rule."""
    rules = tuple(rules)  # a one-shot iterator must not be exhausted by the first event
    findings: List[Finding] = []
    for event in events:
        findings.extend(run_event(event, rules))
    return findings
