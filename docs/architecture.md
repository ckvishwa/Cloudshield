# CloudShield Architecture

CloudShield is a GCP detection-engineering lab. Status labels below are
accurate as of this commit: "implemented" means code and tests exist,
"defined" means Terraform is written and validated but **not applied**, and
"planned" means not started.

## End-to-end flow

```
GitHub / Terraform                     (defined, validated, not applied)
        |
GCP Project                            (defined: APIs, VPC, subnet)
        |
IAM + Service Accounts                 (defined: prod-admin, ci-deployer, app-runtime)
        |
Cloud Audit Logs                       (Admin Activity is platform-default; ingestion planned)
        |
CloudShield Normalizer                 (implemented: telemetry/gcp_audit.py)
        |
Rule Runner                            (implemented: engine/runner.py, engine/rule_loader.py)
        |
Findings                               (implemented: models.Finding with evidence)
```

Only the last three stages run today, against hand-built audit-log fixtures.
Feeding them real Cloud Audit Logs from the Terraform-defined project is the
next milestone.

## Detection engine (implemented)

```
Raw GCP audit JSON -> normalize_gcp_audit_event() -> NormalizedEvent
NormalizedEvent -> run_event()/run_events() -> evaluate_rule() per YAML rule -> Finding
```

- Rules are YAML under `rules/`, loaded by `load_rules()` (deterministic order,
  fail-fast on invalid rules or duplicate IDs).
- The runner only sees `NormalizedEvent`, so new telemetry sources reuse it.
- Implemented detections: GCP-IAM-001, GCP-IAM-002.

## GCP lab infrastructure (Terraform, `terraform/`)

Validated with `terraform fmt`, `init` and `validate`. **Not applied to any
project.**

| Piece | Resources |
|-------|-----------|
| Root | `google_project_service` for 6 APIs; modules `vpc`, `iam` |
| `modules/vpc` | custom-mode VPC `cloudshield-vpc`, subnet `cloudshield-subnet` (`10.20.0.0/24`), no firewall rules |
| `modules/iam` | service accounts `prod-admin`, `ci-deployer`, `app-runtime`; resource-level token-creator bindings on `prod-admin` |
| `modules/gke` | empty on purpose; GKE is a later task |

### Identities and impersonation lab support

| Service account | Project roles | Purpose |
|-----------------|---------------|---------|
| `prod-admin` | none | "Protected" identity that GCP-IAM-002 watches. Not actually privileged. |
| `ci-deployer` | none | Approved caller. Holds `roles/iam.serviceAccountTokenCreator` on `prod-admin` only. |
| `app-runtime` | none | Low-privilege workload identity for later scenarios. |

- No service account keys are created. Impersonation is keyless.
- `roles/iam.serviceAccountTokenCreator` on `prod-admin` lets the holder mint
  tokens, ID tokens, signed JWTs and signed blobs as `prod-admin`, so it is
  equivalent to holding everything `prod-admin` can do. It is bound to that one
  service account, never at project level.
- Extra callers (to produce a GCP-IAM-002 finding on purpose) are listed in
  `impersonation_test_principals`. It is empty by default and validation rejects
  wildcards, `allUsers`, `allAuthenticatedUsers` and `domain:` members.
- The GCP-IAM-002 rule ships with `cloudshield-lab` in its example service
  account emails. If the deployed project ID differs, update the protected and
  approved lists in `rules/iam/service_account_impersonation.yaml`.

### Audit logging

- Admin Activity audit logs (IAM policy changes, service account creation,
  `GenerateAccessToken`/`SignJwt`/... on `iamcredentials.googleapis.com`) are
  always on and need no configuration, which is why nothing is enabled for them.
- Data Access audit logs are **not** enabled project-wide (cost and noise). If a
  later detection needs them, enable them per service with
  `google_project_iam_audit_config`.
- VPC Flow Logs are not enabled yet; they arrive with the network detections.

### Known bootstrap step

Terraform cannot enable `serviceusage` or `cloudresourcemanager` on a brand-new
project by itself. Run once:
`gcloud services enable serviceusage.googleapis.com cloudresourcemanager.googleapis.com`.
