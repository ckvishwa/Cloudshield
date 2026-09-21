import copy
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

from cloudshield.dataset import (
    DatasetEvent,
    DatasetValidationError,
    find_sensitive_content,
    load_dataset,
    validate_dataset,
)
from cloudshield.engine.rule_binding import bind_service_account_impersonation_rule
from cloudshield.engine.rule_loader import load_rules
from cloudshield.engine.runner import run_event
from cloudshield.evaluation import evaluate_dataset
from cloudshield.telemetry.gcp_audit import normalize_gcp_audit_event

ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = ROOT / "datasets" / "gcp_audit"
RULE_IDS = ["GCP-IAM-001", "GCP-IAM-002"]

sys.path.insert(0, str(ROOT / "scripts"))
import replay_dataset  # noqa: E402  (CLI module, imported for its rule binding and main())


@pytest.fixture(scope="module")
def rules():
    return replay_dataset._bind_rules(load_rules(ROOT / "rules"))


@pytest.fixture(scope="module")
def dataset(rules):
    return load_dataset(DATASET_DIR, [r.rule_id for r in rules])


def _fired(event, rules):
    return sorted(f.rule_id for f in run_event(normalize_gcp_audit_event(event.raw), rules))


def _event(event_id="e1", **overrides):
    values = dict(event_id=event_id, source_type="official_example", source_reference="ref",
                  parent_event_id=None, expected_rules=(), raw={"n": event_id})
    values.update(overrides)
    return DatasetEvent(**values)


# ---- corpus loads and is well-formed ------------------------------------------

def test_rules_directory_loads_strictly():
    assert [r.rule_id for r in load_rules(ROOT / "rules")] == RULE_IDS


def test_corpus_loads_with_expected_composition(dataset):
    counts = Counter(e.source_type for e in dataset.events)

    assert len(dataset.events) >= 30
    assert counts == {"official_example": 8, "synthetic_variant": 27}
    assert dataset.manifest["event_counts"]["total"] == len(dataset.events)


def test_corpus_has_the_requested_mix(dataset):
    tags = Counter(t for e in dataset.events for t in e.tags)

    assert sum(1 for e in dataset.events if {"iam001", "true_positive"} <= set(e.tags)) == 5
    assert sum(1 for e in dataset.events if {"iam001", "negative_control"} <= set(e.tags)) == 5
    assert sum(1 for e in dataset.events
               if {"iam002", "true_positive"} <= set(e.tags) and "boundary" not in e.tags) == 5
    assert sum(1 for e in dataset.events if {"iam002", "negative_control"} <= set(e.tags)) == 5
    assert tags["unrelated_benign"] == 5
    assert sum(1 for e in dataset.events if "malformed" in e.tags or "boundary" in e.tags) == 5


def test_synthetic_events_reference_a_real_non_synthetic_parent(dataset):
    by_id = {e.event_id: e for e in dataset.events}

    for event in dataset.events:
        if event.source_type == "synthetic_variant":
            assert by_id[event.parent_event_id].source_type != "synthetic_variant"
        else:
            assert event.parent_event_id is None


def test_labels_are_kept_out_of_the_raw_telemetry(dataset):
    for event in dataset.events:
        assert not {"expected_rules", "event_id", "source_type", "source_reference"} & set(event.raw)
        assert "expected_rules" not in json.dumps(event.raw)


# ---- detections against the corpus ---------------------------------------------

def test_iam_001_true_positives_are_detected(dataset, rules):
    positives = [e for e in dataset.events if {"iam001", "true_positive"} <= set(e.tags)]

    assert len(positives) == 5
    for event in positives:
        assert _fired(event, rules) == ["GCP-IAM-001"], event.event_id


def test_iam_002_true_positives_are_detected(dataset, rules):
    positives = [e for e in dataset.events if {"iam002", "true_positive"} <= set(e.tags)]

    assert len(positives) == 6  # five plus the invalid-timestamp boundary event
    for event in positives:
        assert _fired(event, rules) == ["GCP-IAM-002"], event.event_id


def test_negative_controls_and_unrelated_events_stay_negative(dataset, rules):
    for event in dataset.events:
        if not event.expected_rules:
            assert _fired(event, rules) == [], event.event_id


def test_mixed_delta_event_matches_only_the_owner_grant(dataset, rules):
    event = next(e for e in dataset.events if e.event_id == "syn-iam001-tp-owner")
    (finding,) = run_event(normalize_gcp_audit_event(event.raw), rules)

    assert finding.matched_values == {"attributes.roles_added": ["roles/owner"]}
    assert finding.evidence["matched_bindings"] == [{"role": "roles/owner", "member": "user:developer@example.com"}]


def test_official_generate_access_token_example_is_not_protected(dataset, rules):
    event = next(e for e in dataset.events if e.event_id == "off-sa-generate-access-token")
    normalized = normalize_gcp_audit_event(event.raw)

    assert normalized.event_type == "gcp.iam.service_account_credential_generation"
    assert normalized.attributes["target_service_account"] == "my-service-account@my-project.iam.gserviceaccount.com"
    assert _fired(event, rules) == []


def test_documented_false_negative_is_the_only_mismatch(dataset, rules):
    report = evaluate_dataset(dataset.events, rules)

    assert report.mismatches == [{"event_id": "syn-iam001-gap-owner-without-deltas",
                                  "false_positives": [], "false_negatives": ["GCP-IAM-001"]}]


def test_full_corpus_metrics_are_exact_and_deterministic(dataset, rules):
    first = evaluate_dataset(dataset.events, rules).to_dict()
    second = evaluate_dataset(dataset.events, rules).to_dict()

    assert first == second
    assert (first["events"], first["findings"]) == (35, 11)
    assert (first["true_positives"], first["false_positives"], first["false_negatives"]) == (11, 0, 1)
    assert first["true_negatives"] == 35 * 2 - 12
    assert first["precision"] == 1.0
    assert first["recall"] == round(11 / 12, 6)
    assert first["rules"]["GCP-IAM-001"]["false_negatives"] == 1
    assert first["rules"]["GCP-IAM-002"]["true_positives"] == 6


def test_replay_modes_agree_on_results_and_cap_sleep(dataset, rules):
    sleeps = []
    instant = evaluate_dataset(dataset.events, rules)
    accelerated = evaluate_dataset(dataset.events, rules, mode="accelerated", speed=1000,
                                   max_sleep_seconds=0.25, sleep=sleeps.append)

    assert accelerated == instant
    assert sleeps and max(sleeps) <= 0.25


def test_binding_uses_only_the_fictional_project(rules):
    text = json.dumps([r.conditions for r in rules])

    assert "cloudshield-lab" in text


# ---- CLI --------------------------------------------------------------------------

def test_cli_writes_a_deterministic_json_report(tmp_path, capsys):
    out_a, out_b = tmp_path / "a.json", tmp_path / "b.json"

    assert replay_dataset.main(["--dataset", str(DATASET_DIR), "--json-output", str(out_a)]) == 0
    first_stdout = capsys.readouterr().out
    assert replay_dataset.main(["--dataset", str(DATASET_DIR), "--json-output", str(out_b)]) == 0
    second_stdout = capsys.readouterr().out

    assert first_stdout == second_stdout
    assert out_a.read_bytes() == out_b.read_bytes()
    report = json.loads(out_a.read_text(encoding="utf-8"))
    assert report["events"] == 35 and report["true_positives"] == 11
    assert "events processed: 35" in first_stdout and "false negatives: 1" in first_stdout
    assert "benchmark" not in first_stdout


def test_cli_max_events_and_benchmark_flag(capsys):
    assert replay_dataset.main(["--dataset", str(DATASET_DIR), "--max-events", "8", "--benchmark"]) == 0
    out = capsys.readouterr().out

    assert "events processed: 8" in out
    assert "local corpus benchmark" in out and "not a production throughput figure" in out


@pytest.mark.parametrize("argv", [["--speed", "0", "--mode", "accelerated"], ["--max-events", "0"]])
def test_cli_rejects_bad_settings(argv, capsys):
    assert replay_dataset.main(["--dataset", str(DATASET_DIR)] + argv) == 1


def test_cli_reports_invalid_dataset(tmp_path, capsys):
    (tmp_path / "manifest.yaml").write_text("event_counts: {}\n", encoding="utf-8")
    (tmp_path / "corpus.jsonl").write_text('{"nope": 1}\n', encoding="utf-8")

    assert replay_dataset.main(["--dataset", str(tmp_path)]) == 1
    assert "missing keys" in capsys.readouterr().err


# ---- data-quality validation -------------------------------------------------------

def test_valid_events_pass_validation():
    validate_dataset([_event("a", raw={"n": 1}), _event("b", raw={"n": 2})], RULE_IDS)


def test_duplicate_event_ids_fail():
    with pytest.raises(DatasetValidationError, match="duplicate event_id"):
        validate_dataset([_event("a", raw={"n": 1}), _event("a", raw={"n": 2})], RULE_IDS)


def test_duplicate_raw_events_fail():
    with pytest.raises(DatasetValidationError, match="duplicates a"):
        validate_dataset([_event("a", raw={"n": 1}), _event("b", raw={"n": 1})], RULE_IDS)


def test_unknown_rule_ids_fail():
    with pytest.raises(DatasetValidationError, match="unknown rule ID 'NOPE-1'"):
        validate_dataset([_event(expected_rules=("NOPE-1",))], RULE_IDS)


def test_invalid_source_type_fails():
    with pytest.raises(DatasetValidationError, match="invalid source_type"):
        validate_dataset([_event(source_type="scraped_from_prod")], RULE_IDS)


def test_synthetic_provenance_is_required():
    parent = _event("parent", raw={"n": "p"})
    no_parent = _event("v1", source_type="synthetic_variant", raw={"n": 1})
    ghost_parent = _event("v2", source_type="synthetic_variant", parent_event_id="ghost", raw={"n": 2})
    synthetic_parent = _event("v3", source_type="synthetic_variant", parent_event_id="v1", raw={"n": 3})
    official_with_parent = _event("o1", parent_event_id="parent", raw={"n": 4})

    with pytest.raises(DatasetValidationError) as exc:
        validate_dataset([parent, no_parent, ghost_parent, synthetic_parent, official_with_parent], RULE_IDS)

    message = str(exc.value)
    assert "v1: synthetic_variant must reference parent_event_id" in message
    assert "v2: parent_event_id 'ghost' not found" in message
    assert "v3: parent 'v1' must be a non-synthetic example" in message
    assert "o1: only synthetic_variant events may have a parent_event_id" in message


def _write_corpus(tmp_path, lines, counts=None):
    (tmp_path / "corpus.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines), encoding="utf-8")
    manifest = "event_counts: {}\n" if counts is None else f"event_counts: {json.dumps(counts)}\n"
    (tmp_path / "manifest.yaml").write_text(manifest, encoding="utf-8")


def _envelope(**overrides):
    envelope = {"event_id": "a", "source_type": "official_example", "source_reference": "ref",
                "expected_rules": [], "raw": {"n": 1}}
    envelope.update(overrides)
    return envelope


@pytest.mark.parametrize("mutation,message", [
    ({"expected_rules": None}, "expected_rules must be a list"),
    ({"source_reference": ""}, "source_reference must be a non-empty string"),
    ({"raw": "text"}, "raw must be a JSON object"),
    ({"surprise": 1}, "unknown keys"),
])
def test_malformed_envelopes_fail_loudly(tmp_path, mutation, message):
    _write_corpus(tmp_path, [_envelope(**mutation)])

    with pytest.raises(DatasetValidationError, match=message):
        load_dataset(tmp_path, RULE_IDS)


def test_missing_expected_rules_and_provenance_keys_fail(tmp_path):
    envelope = _envelope()
    del envelope["expected_rules"]
    del envelope["source_reference"]
    _write_corpus(tmp_path, [envelope])

    with pytest.raises(DatasetValidationError, match="missing keys"):
        load_dataset(tmp_path, RULE_IDS)


def test_manifest_counts_must_match_the_corpus(tmp_path):
    _write_corpus(tmp_path, [_envelope()], counts={"official_example": 9, "total": 9})

    with pytest.raises(DatasetValidationError, match="do not match"):
        load_dataset(tmp_path, RULE_IDS)


@pytest.mark.parametrize("raw", [
    {"response": {"accessToken": "abc"}},
    {"token": "ya29.a0AfH6SMBexampleexampleexample"},
    {"key": "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"},
    {"cred": {"refresh_token": "x", "client_secret": "y"}},
    {"jwt": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"},
    {"principalEmail": "real.person@gmail.com"},
    {"principalEmail": "someone@company.io"},
    {"callerIp": "8.8.8.8"},
    {"callerIp": "10.0.0.5"},
])
def test_credentials_and_personal_identifiers_are_rejected(raw):
    with pytest.raises(DatasetValidationError):
        validate_dataset([_event(raw=raw)], RULE_IDS)


@pytest.mark.parametrize("raw", [
    {"method": "GenerateAccessToken"},
    {"email": "developer@example.com", "sa": "prod-admin@cloudshield-lab.iam.gserviceaccount.com"},
    {"callerIp": "203.0.113.44", "other": "198.51.100.9", "third": "192.0.2.1"},
])
def test_fictional_values_and_method_names_are_accepted(raw):
    validate_dataset([_event(raw=raw)], RULE_IDS)


def test_timestamp_validation():
    with pytest.raises(DatasetValidationError, match="invalid timestamp"):
        validate_dataset([_event(raw={"timestamp": "yesterday"})], RULE_IDS)
    validate_dataset([_event(raw={"timestamp": "yesterday"}, tags=("invalid_timestamp",))], RULE_IDS)
    with pytest.raises(DatasetValidationError, match="not invalid"):
        validate_dataset([_event(raw={"timestamp": "2024-08-05T10:00:00Z"}, tags=("invalid_timestamp",))], RULE_IDS)
    validate_dataset([_event(raw={"n": "no timestamp at all"})], RULE_IDS)


def test_all_problems_are_reported_together():
    events = [_event("a", raw={"n": 1}, source_type="bogus"), _event("a", raw={"n": 1}, expected_rules=("X",))]

    with pytest.raises(DatasetValidationError, match="4 dataset problem"):
        validate_dataset(events, RULE_IDS)


def test_validation_does_not_mutate_events():
    events = [_event("a", raw={"n": 1})]
    snapshot = copy.deepcopy(events)
    validate_dataset(events, RULE_IDS)

    assert events == snapshot


# ---- secret scan over every dataset file -------------------------------------------

def test_dataset_files_contain_no_credential_material():
    files = [p for p in DATASET_DIR.rglob("*") if p.is_file()]

    assert {p.name for p in files} >= {"corpus.jsonl", "manifest.yaml", "sources.md", "README.md"}
    for path in files:
        assert find_sensitive_content(path.read_text(encoding="utf-8")) == [], path.name


def test_rule_binding_still_rejects_a_real_looking_project_injection():
    rule = next(r for r in load_rules(ROOT / "rules") if r.rule_id == "GCP-IAM-002")

    with pytest.raises(ValueError):
        bind_service_account_impersonation_rule(rule, 'x" OR "1')
