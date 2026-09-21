# Cloudshield

## Detections

| Rule ID | Title |
|---------|-------|
| GCP-IAM-001 | High-Risk IAM Role Granted |
| GCP-IAM-002 | Suspicious Service Account Credential Generation |

## Architecture

```
Normalized Event
      |
Generic Rule Runner        (engine/runner.py: run_event / run_events)
      |
Detection-as-Code Rules    (rules/**/*.yaml, engine/rule_loader.py: load_rules)
      |
Findings
```

`load_rules()` recursively loads every `*.yaml` / `*.yml` rule in a stable
path order and fails on invalid rules or duplicate rule IDs. `run_event()`
evaluates one `NormalizedEvent` against every rule and returns 0..N findings.
Cost is O(events x rules); there is no rule indexing yet.

## Offline GCP Audit Replay

The primary, fully offline way to exercise the detections: no GCP project,
billing, credentials or API calls.

```
GCP audit dataset (JSON / JSONL) -> ingestion -> provenance + expected labels
  -> replay (instant | accelerated | realtime) -> normalize_gcp_audit_event()
  -> load_rules() -> run_event() -> findings -> TP / FP / FN evaluation
```

- `datasets/gcp_audit/`: a labeled corpus of 35 GCP Cloud Audit Log events:
  8 copied or reformatted from Google's documentation (`official_example`) and
  27 authored variants (`synthetic_variant`), each tied to a parent example.
  Synthetic events are not real telemetry. See `datasets/gcp_audit/sources.md`.
- `telemetry/file_ingest.py`: bounded, UTF-8 JSON / JSONL loading with line-numbered errors.
- `dataset.py`: envelope model (provenance and labels kept outside the raw event) and
  data-quality validation (duplicates, unknown rules, provenance, credentials,
  non-fictional emails/IPs, timestamps).
- `replay.py`: replay modes with sleep caps and safe handling of bad timestamps.
- `evaluation.py`: per-event, multi-label TP / FP / FN with precision, recall and F1, overall and per rule.

```
python scripts/replay_dataset.py --dataset datasets/gcp_audit --mode instant
```

These are corpus-specific evaluation results, not production accuracy. The
corpus was authored together with the rules, so it is a regression and
coverage check rather than an independent measurement. It contains one
documented false negative: a `SetIamPolicy` entry that grants `roles/owner`
but carries no `bindingDeltas`.

The Cloud Logging API backend is optional and not required for this workflow.

## GCP Lab Infrastructure

Terraform (`terraform/`) defines the GCP lab that future real Cloud Audit Logs
will come from:

- required APIs: cloudresourcemanager, compute, iam, iamcredentials, logging, serviceusage
- custom-mode VPC `cloudshield-vpc` with one private subnet (`10.20.0.0/24`) and no firewall rules
- service accounts `prod-admin` (protected), `ci-deployer` (approved caller), `app-runtime`; no keys, no project roles
- impersonation lab foundation: `roles/iam.serviceAccountTokenCreator` scoped to the single `prod-admin` service account
- audit logging: GCP-IAM-001 uses Admin Activity logs (always on); GCP-IAM-002 needs Data Access logs, enabled for `iam.googleapis.com` only (Service Account Credentials cannot be configured independently)
- the optional Cloud Logging backend (`telemetry/gcp_logging.py`, `scripts/live_validate.py`) is implemented and unit-tested with a mocked client, but has never been run against a real project

**Status: Terraform validation completed (`fmt`, `init`, `validate`). Nothing has been applied; no GCP resources exist yet.**

```
cd terraform
cp terraform.tfvars.example terraform.tfvars   # git-ignored; set project_id
terraform init && terraform validate
```

See `docs/architecture.md` for details and the security notes.
