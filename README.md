# Cloudshield

## Detections

| Rule ID | Title |
|---------|-------|
| GCP-IAM-001 | High-Risk IAM Role Granted |
| GCP-IAM-002 | Suspicious Service Account Credential Generation |
| GCP-IAM-003 | High-Risk Role Present in IAM Policy Update |
| K8S-WORKLOAD-001 | Privileged Pod Created or Updated |
| K8S-RBAC-001 | Cluster-Admin ClusterRoleBinding Created or Updated |

**GCP-IAM-001 vs GCP-IAM-003.** Both look at `SetIamPolicy` audit entries but mean different things:

- **GCP-IAM-001** (HIGH) fires on a high-confidence signal: an `ADD` binding delta for a high-risk role. The role was granted by this call.
- **GCP-IAM-003** (MEDIUM) fires on a lower-confidence signal: the policy snapshot returned by the call (`response.bindings`, else `request.policy.bindings`) contains a high-risk role and the entry has no usable binding delta. It does not say the role was granted; the role may have been there already.

If an entry has a binding delta, only GCP-IAM-001 can fire, so one change never alerts twice. The two rules keep an identical high-risk role list (a test enforces it).

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

- `datasets/gcp_audit/`: a labeled corpus of 49 GCP Cloud Audit Log events:
  8 copied or reformatted from Google's documentation (`official_example`) and
  41 authored variants (`synthetic_variant`), each tied to a parent example.
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
coverage check rather than an independent measurement. Its first version
exposed a GCP-IAM-001 gap (a `SetIamPolicy` snapshot containing `roles/owner`
with no `bindingDeltas`); that led to GCP-IAM-003 rather than to weakening
GCP-IAM-001. See `datasets/gcp_audit/README.md`.

The Cloud Logging API backend is optional and not required for this workflow.

## Kubernetes / GKE Audit Replay

Kubernetes is CloudShield's second telemetry family. It reuses the same rule
runner, rule loader, dataset framework and evaluation as the GCP audit
pipeline; only the normalizer differs.

- **Native Kubernetes audit events** (`audit.k8s.io/v1` `Event`) and **GKE Cloud
  Audit Log wrappers** (`protoPayload.serviceName: k8s.io`) both normalize
  through `telemetry/kubernetes_audit.py` into the same stable attributes
  (verb, API group, resource, namespace, name, source IPs, cluster labels).
- **Two detections**, both plain YAML on the generic engine:
  - `K8S-WORKLOAD-001` (HIGH): a Pod create/update/patch where a container,
    initContainer or ephemeralContainer sets `securityContext.privileged: true`.
    `allowPrivilegeEscalation` does not count. If the audit level provides no
    request body the result is unknown, not "not privileged".
  - `K8S-RBAC-001` (HIGH): a ClusterRoleBinding create/update/patch whose
    `roleRef` is `ClusterRole` / `cluster-admin`. A namespaced RoleBinding is not
    covered.
- Failed writes (non-2xx, or a non-zero GKE status) and the `RequestReceived`
  stage do not produce findings; if a log has no status the outcome is treated
  as unknown, not as confirmed success.
- **Offline corpus:** `datasets/kubernetes_audit/` holds 51 labeled events.
  Every one is a `synthetic_variant` derived from Kubernetes and GKE
  documentation; no complete official sample was available to copy, and
  synthetic events are not real telemetry. See `datasets/kubernetes_audit/sources.md`.
- The dataset manifest declares `telemetry_type`, which selects the normalizer.

```
python scripts/replay_dataset.py --dataset datasets/kubernetes_audit --mode instant
```

**No live GKE validation has been done.** There is no GKE cluster, no
GKE log backend, and nothing was checked against real GKE audit logs; the GKE
wrapper shape is inferred from documented query fields. This is a lab
exercise, not production experience.

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
