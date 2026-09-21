"""Replay a labeled audit dataset (GCP or Kubernetes) through the CloudShield detections.

The dataset manifest's telemetry_type selects the normalizer.

Fully offline: no GCP API calls, no credentials, no network. Default output is
deterministic; timing is printed only with --benchmark.

Example:
    python scripts/replay_dataset.py --dataset datasets/gcp_audit --mode instant
"""
import argparse
import json
import sys
import time
from pathlib import Path

from cloudshield.dataset import DatasetValidationError, load_dataset
from cloudshield.engine.rule_binding import bind_service_account_impersonation_rule
from cloudshield.engine.rule_loader import load_rules
from cloudshield.evaluation import evaluate_dataset
from cloudshield.replay import MODE_INSTANT, MODES
from cloudshield.telemetry.file_ingest import IngestError
from cloudshield.telemetry.registry import get_adapter

REPO_ROOT = Path(__file__).resolve().parent.parent
FICTIONAL_PROJECT = "cloudshield-lab"


def _bind_rules(rules):
    """Bind GCP-IAM-002 to the fictional lab project (never a real project)."""
    return [
        bind_service_account_impersonation_rule(
            rule, FICTIONAL_PROJECT, protected_accounts=("prod-admin", "deployment-admin"),
            approved_callers=("ci-deployer",))
        if rule.rule_id == "GCP-IAM-002" else rule
        for rule in rules
    ]


def _fmt(value):
    return "n/a" if value is None else f"{value:.4f}"


def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dataset", default=str(REPO_ROOT / "datasets" / "gcp_audit"),
                        help="dataset directory (corpus.jsonl + manifest.yaml)")
    parser.add_argument("--mode", choices=MODES, default=MODE_INSTANT)
    parser.add_argument("--speed", type=float, default=1.0, help="accelerated-mode speed multiplier (> 0)")
    parser.add_argument("--max-events", type=int, help="replay only the first N events")
    parser.add_argument("--json-output", metavar="PATH", help="also write the report as JSON")
    parser.add_argument("--rules-dir", default=str(REPO_ROOT / "rules"))
    parser.add_argument("--benchmark", action="store_true", help="print local wall-clock timing")
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    if args.max_events is not None and args.max_events < 1:
        print("--max-events must be >= 1", file=sys.stderr)
        return 1
    try:
        rules = _bind_rules(load_rules(args.rules_dir))
        dataset = load_dataset(args.dataset, [rule.rule_id for rule in rules])
        events = dataset.events[: args.max_events] if args.max_events else dataset.events
        started = time.perf_counter()
        report = evaluate_dataset(
            events, rules, mode=args.mode, speed=args.speed, adapter=get_adapter(dataset.telemetry_type),
            score_rules=dataset.manifest.get("rules_covered") or None)
        elapsed = time.perf_counter() - started
    except (DatasetValidationError, IngestError, ValueError, FileNotFoundError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"dataset: {args.dataset} (telemetry_type={dataset.telemetry_type}, mode={args.mode})")
    print(f"events processed: {report.events}")
    print(f"findings: {report.findings}")
    print(f"true positives: {report.true_positives}")
    print(f"false positives: {report.false_positives}")
    print(f"false negatives: {report.false_negatives}")
    print(f"true negatives (event x rule pairs): {report.true_negatives}")
    print(f"precision: {_fmt(report.precision)}  recall: {_fmt(report.recall)}  f1: {_fmt(report.f1)}")
    print("per rule:")
    for rule_id, score in report.rules.items():
        print(f"  {rule_id}: TP={score.true_positives} FP={score.false_positives} FN={score.false_negatives} "
              f"precision={_fmt(score.precision)} recall={_fmt(score.recall)} f1={_fmt(score.f1)}")
    if report.mismatches:
        print("mismatches:")
        for mismatch in report.mismatches:
            print(f"  {mismatch['event_id']}: FP={mismatch['false_positives']} FN={mismatch['false_negatives']}")
    print("note: results describe this corpus only, not production accuracy.")
    if args.benchmark:
        rate = report.events / elapsed if elapsed > 0 else float("inf")
        print(f"local corpus benchmark: {report.events} events in {elapsed:.4f}s ({rate:.0f} events/sec); "
              "not a production throughput figure")

    if args.json_output:
        Path(args.json_output).write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
