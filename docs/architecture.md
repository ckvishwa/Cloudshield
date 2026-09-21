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
Cloud Audit Logs                       (Admin Activity default; IAM Data Access defined; ingestion planned)
        |
CloudShield Normalizer                 (implemented: telemetry/gcp_audit.py)
        |
Rule Runner                            (implemented: engine/runner.py, engine/rule_loader.py)
        |
Findings                               (implemented: models.Finding with evidence)
```

The Terraform stages are **validated, not deployed**: no GCP resources exist
and no billing is attached. The last three stages run today against an offline
corpus (below) and hand-built fixtures. Nothing has been validated against live
GCP.

## Telemetry sources

```
              Telemetry
            /           \
   Offline dataset      Cloud Logging API
   (implemented, used)  (implemented, optional, never run live)
            \           /
        normalize_gcp_audit_event()
                  |
              Rule runner
                  |
               Findings
```

| Component | Status |
|-----------|--------|
| Offline replay (`telemetry/file_ingest.py`, `dataset.py`, `replay.py`, `evaluation.py`, `scripts/replay_dataset.py`, `datasets/gcp_audit/`) | implemented and tested |
| Cloud Logging API backend (`telemetry/gcp_logging.py`, `scripts/live_validate.py`) | implemented, unit-tested with a mocked client, not required, no live run |
| Terraform lab (`terraform/`) | validated, not deployed |

### Offline replay

- The corpus keeps provenance (`source_type`: `official_example`,
  `public_sanitized_example`, `synthetic_variant`) and expected rule IDs in an
  envelope beside the raw event; nothing CloudShield-specific enters
  `protoPayload`.
- Loading validates the corpus (duplicate IDs and events, unknown rule IDs,
  provenance, credential-like strings, non-fictional emails and IPs, timestamps)
  and fails loudly.
- Replay modes: `instant` (no sleep; tests and evaluation), `accelerated`
  (timestamp gap divided by speed) and `realtime`. Every sleep is capped
  (default 10 s), and missing, invalid or backwards timestamps never sleep, so
  a bad timestamp cannot stall a replay.
- Evaluation compares the set of rule IDs that fired with the expected set per
  event, so multi-label events are scored per rule. Results describe the corpus
  only.

## Detection engine (implemented)

```
Raw GCP audit JSON -> normalize_gcp_audit_event() -> NormalizedEvent
NormalizedEvent -> run_event()/run_events() -> evaluate_rule() per YAML rule -> Finding
```

- Rules are YAML under `rules/`, loaded by `load_rules()` (deterministic order,
  fail-fast on invalid rules or duplicate IDs).
- The runner only sees `NormalizedEvent`, so new telemetry sources reuse it.
- Implemented detections: GCP-IAM-001, GCP-IAM-002, GCP-IAM-003.

### Two IAM policy signals

```
SetIamPolicy audit entry
   |-- usable ADD/REMOVE binding delta ----------> roles_added / roles_removed --> GCP-IAM-001 (HIGH)
   |-- policy snapshot, no usable delta ---------> roles_present_after ----------> GCP-IAM-003 (MEDIUM)
        (response.bindings, else request.policy.bindings; never merged)
```

- `roles_added` and `roles_removed` come only from binding deltas, which prove a
  change. `roles_present_after` comes from a policy snapshot, which only shows
  what the policy contains afterwards. A snapshot is never used to fill
  `roles_added`, because a role in the snapshot may have been granted long ago.
- The normalizer recognizes a policy change from a binding delta, or from a
  method whose final component is exactly `SetIamPolicy` (case-insensitive, so
  `SetIAMPolicy` matches; `NotSetIamPolicy` and `SetIamPolicyPreview` do not).
  A `bindings` field on an unrelated method does not make an event a policy change.
- `policy_delta_present` is true when at least one well-formed ADD/REMOVE delta
  exists. GCP-IAM-003 requires it to be false, so an event with a delta is
  covered only by the higher-confidence GCP-IAM-001 and does not alert twice.
- Snapshot bindings are reduced to `{role, members}`; malformed bindings are
  skipped, and etags, conditions and the rest of the response are not copied.
- Evidence keeps each matched role with only its own members, for both signals.

The two stay separate because they answer different questions. Merging them
would either label an unproven role "granted" or bury the confirmed grant among
lower-confidence findings.

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

| Detection | Log type it needs | How it is available |
|-----------|-------------------|---------------------|
| GCP-IAM-001, GCP-IAM-003 (IAM policy changes via `SetIamPolicy`) | Admin Activity | Always on; nothing to configure. |
| GCP-IAM-002 (`GenerateAccessToken`, `GenerateIdToken`, `SignJwt`, `SignBlob` on `iamcredentials.googleapis.com`) | **Data Access** | Off by default. Terraform defines it (see below); not applied yet. |

Service Account Credentials audit events are Data Access logs, not Admin
Activity. Data Access logging cannot be enabled for
`iamcredentials.googleapis.com` on its own; Google's documented way is to
enable it for the IAM API (`iam.googleapis.com`), which also covers the Service
Account Credentials API. Terraform does this with one
`google_project_iam_audit_config` for `iam.googleapis.com`:

- `ADMIN_READ`: `GenerateAccessToken` is an ADMIN_READ method.
- `DATA_READ`: `GenerateIdToken`, `SignJwt` and `SignBlob` are DATA_READ and
  ADMIN_READ methods.
- `DATA_WRITE` is not enabled; none of these methods need it.
- No exempted members.

Consequences:

- Scope is IAM only. Data Access logging is not enabled for all services.
- Other IAM API read calls (e.g. `GetServiceAccount`) are logged too, which adds
  some volume and cost.
- The resource is authoritative for `iam.googleapis.com`: it replaces any log
  types or exempted members already configured for that service and does not
  touch other services. Destroying it removes the IAM audit config.
- Until the config is applied, GCP-IAM-002 has no real telemetry to fire on.
- VPC Flow Logs are not enabled yet; they arrive with the network detections.

### Known bootstrap step

Terraform cannot enable `serviceusage` or `cloudresourcemanager` on a brand-new
project by itself. Run once:
`gcloud services enable serviceusage.googleapis.com cloudresourcemanager.googleapis.com`.
