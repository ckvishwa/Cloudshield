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
and no billing is attached. The last three stages run today against the offline
corpora (below) and hand-built fixtures. Nothing has been validated against live
GCP.

## Telemetry sources

CloudShield has two telemetry families. Each has its own normalizer and both
produce the same `NormalizedEvent`, so the rule runner is shared.

```
                          Telemetry
              /                                \
        GCP Audit                       Kubernetes Audit
        /       \                       /              \
  offline       Cloud Logging      native           GKE Cloud Audit
  dataset       API (optional)     audit Event      Log wrapper
      \            /                   \               /
    gcp_audit normalizer         kubernetes_audit normalizer
                  \                     /
                   NormalizedEvent
                          |
                   Generic rule runner
                          |
                 Detection-as-code rules
                          |
                       Findings
```

| Component | Status |
|-----------|--------|
| GCP offline corpus (`datasets/gcp_audit/`) | implemented and tested |
| Kubernetes / GKE offline corpus (`datasets/kubernetes_audit/`) | implemented and tested (synthetic events, no complete official samples) |
| Replay pipeline (`telemetry/file_ingest.py`, `dataset.py`, `replay.py`, `evaluation.py`, `telemetry/registry.py`, `scripts/replay_dataset.py`) | implemented and tested; the dataset manifest's `telemetry_type` selects the normalizer |
| GCP live backend: Cloud Logging API (`telemetry/gcp_logging.py`, `scripts/live_validate.py`) | implemented, unit-tested with a mocked client, not live validated, not required |
| GKE live backend | **not implemented** |
| Terraform lab (`terraform/`) | validated, not deployed; no GKE cluster is defined |

### Kubernetes / GKE telemetry

`telemetry/kubernetes_audit.py` normalizes two shapes chosen by explicit shape
checks (never by a single field): a native `audit.k8s.io` `Event`
(`apiVersion` starting `audit.k8s.io/`, `kind: Event`) and a GKE Cloud Audit Log
wrapper (`protoPayload.serviceName == "k8s.io"` and `resource.type ==
"k8s_cluster"`). Any other input, including an ordinary GCP audit entry, becomes
a generic event with `format = None`.

- Stable attributes are independent of the input shape: `verb`, `api_group`,
  `resource`, `subresource`, `namespace`, `name`, `source_ips`, `username`,
  `groups`, cluster labels, plus `operation_succeeded`. Consumers do not parse
  GKE method names.
- Event types: `k8s.workload.change` (Pod create/update/patch),
  `k8s.rbac.binding_change` (ClusterRoleBinding create/update/patch),
  `k8s.pod.exec` (pods/exec), `k8s.secret.access` (Secret get/list/watch) and
  `k8s.audit.generic` for everything else, including other reads, deletes,
  other subresources and failed requests.
- Stage: native events are actionable only at `ResponseComplete`; one API request
  emits several stages and the others are suppressed to avoid duplicate alerts.
- Outcome: a native status code outside 2xx (HTTP 101, the normal result of an
  exec upgrade, counts as success), or a non-zero GKE gRPC status, routes the
  event to generic. A missing status means the outcome is unknown; it
  is neither confirmed as success nor treated as failure.
- Security facts are derived in the normalizer, not by the rule engine:
  `has_privileged_container` is true, false (request body inspected) or null
  (no inspectable body), and only true matches. `allowPrivilegeEscalation` is
  not `privileged`. RBAC facts are `rbac_role_ref_kind`, `rbac_role_ref_name`
  and compact `rbac_subjects`.
- Response bodies are never read and Secret objects are never copied.
- **Raw telemetry is input-only.** `NormalizedEvent.raw` is always `{}` for
  Kubernetes telemetry. The adapter extracts only the minimal facts detections
  need into `attributes`, and the detection engine and findings never see the
  original event. Request and response bodies can carry Secret `data` /
  `stringData`, tokens or other user-supplied content, so they are not retained
  or "redacted after the fact"; they are simply not kept. This matters most for
  Secret-bearing events.
- Assumption to verify on real logs: the GKE `protoPayload.request` is the
  Kubernetes object itself. See `datasets/kubernetes_audit/sources.md`.

Rules (all plain YAML on the generic engine):

| Rule | Severity | Event type | Meaning | ATT&CK |
|------|----------|------------|---------|--------|
| K8S-WORKLOAD-001 | HIGH | `k8s.workload.change` | Pod with a privileged container | T1610 |
| K8S-WORKLOAD-002 | HIGH | `k8s.workload.change` | Pod with hostNetwork/hostPID/hostIPC, a hostPath volume, or added SYS_ADMIN / SYS_PTRACE | T1610 |
| K8S-RBAC-001 | HIGH | `k8s.rbac.binding_change` | ClusterRoleBinding to `cluster-admin` | T1098.006 |
| K8S-EXEC-001 | MEDIUM | `k8s.pod.exec` | Successful (or unknown-outcome) pods/exec | T1609 |
| K8S-SECRET-001 | HIGH | `k8s.secret.access` | Secret get / list / watch | T1552.007 |

Normalized facts added in T-008 (an explicit allowlist; no request or response
body is copied):

- **Exec:** `is_exec` (pods/exec with verb create, get or connect, core group).
  The pod is `namespace` / `name`; the command run is not in the audit event and
  is not captured.
- **Secret access:** `secret_access_type` (`read` for get, `enumeration` for list,
  `watch`) and `secret_name`. Secret objects are never copied.
- **Dangerous workload:** `host_network`, `host_pid`, `host_ipc` (only the
  boolean true counts), `host_path_volumes` (`{name, path, read_only}`, where
  `read_only` comes from the volumeMounts that use the volume), `dangerous_capabilities`
  (upper-cased, `CAP_` stripped, from an explicit set: SYS_ADMIN, SYS_PTRACE),
  `dangerous_capability_containers`, and the tri-state `has_dangerous_host_config`.
  containers, initContainers and ephemeralContainers are all inspected.

Decisions and semantics:

- **Failed exec is not alerted.** A denied exec ran nothing. This is a deliberate
  choice; exec attempts would need a separate rule.
- **Exec is notable, not malicious.** MEDIUM severity; exec is routine debugging.
- **All Secret access types are HIGH.** get returns one Secret, list and watch
  return every Secret they cover, so each exposes Secret contents to the caller.
  This does not mean a secret was stolen or exfiltrated, and system controllers
  read Secrets routinely, so expect noise from system identities.
- **Dangerous host config is a configuration finding.** It does not show a
  container escape. T1611 (Escape to Host) is what such settings could enable, but
  no escape is observed, so the rules map to T1610 (Deploy Container).
- **Unknown is not false.** `has_dangerous_host_config` and
  `has_privileged_container` are null when the audit level gave no request body,
  and only true matches.

Limitations:

- Secret access is only visible if the audit policy records Secret requests
  (Metadata level or higher); pods exec likewise needs the request logged. GKE's
  default policy and any custom policy decide this; nothing here was checked on a
  real cluster.
- Native events are actionable only at `ResponseComplete`. A long-running exec or
  watch may only be logged at `ResponseStarted` in some setups, and would then be
  missed until its `ResponseComplete` entry appears.
- Offline corpus validation does not prove the live GKE telemetry shape.
- Not covered: privileged or host-level settings inside Deployments and other
  controllers, namespaced RoleBindings to cluster-admin, `pods/attach` and
  `pods/portforward`, capabilities other than SYS_ADMIN / SYS_PTRACE (such as
  `ALL`, NET_ADMIN, SYS_MODULE), Secret volume mounts and env references, and
  the exec command itself.

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
- Telemetry adapters are the sanitization boundary: they extract the facts a detection needs and drop the rest. The Kubernetes adapter does not retain the raw event at all; the GCP audit adapter still attaches its input as `NormalizedEvent.raw`. That is a known gap, not a design choice; its offline corpus is synthetic or official-doc content and the optional Cloud Logging adapter already whitelists fields before normalization.
- Implemented detections: GCP-IAM-001, GCP-IAM-002, GCP-IAM-003, K8S-WORKLOAD-001, K8S-RBAC-001.

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
