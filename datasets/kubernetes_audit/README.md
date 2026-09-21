# Kubernetes / GKE audit corpus

A labeled corpus of Kubernetes audit telemetry for offline replay and
evaluation of CloudShield's Kubernetes detections. See `sources.md` for
provenance. All 106 events are `synthetic_variant`: authored for CloudShield from
documented field references, not real telemetry.

- `corpus.jsonl`: one envelope per line (`event_id`, `source_type`,
  `source_reference`, `derived_from`, `expected_rules`, `raw`, `tags`,
  `description`). Labels never enter `raw`.
- `manifest.yaml`: declares `telemetry_type: kubernetes_audit`, which selects the
  Kubernetes normalizer, plus the rules covered and expected counts.
- `sources.md`: documentation the shapes were derived from, and the assumptions.

## Two telemetry shapes

- **Native Kubernetes audit Event** (`audit.k8s.io/v1`, `kind: Event`).
- **GKE Cloud Audit Log wrapper** (`protoPayload.serviceName: k8s.io`,
  `resource.type: k8s_cluster`).

Both normalize to the same `NormalizedEvent` semantics; the corpus contains a
privileged-pod pair and a cluster-admin-binding pair that must behave the same in
either shape.

## Composition

| Group | Events |
|-------|--------|
| K8S-WORKLOAD-001 true positives | 7 (regular container, init container, multi-container, update, patch, unknown outcome, GKE) |
| K8S-WORKLOAD-001 negative controls | 13 (privileged false, no securityContext, allowPrivilegeEscalation only, GET, Deployment out of scope, unrelated resource, malformed containers, no request body, failed writes, RequestReceived stage, string "true", pods/status) |
| K8S-RBAC-001 true positives | 7 (create, update, patch, multiple subjects, unauthenticated group, unknown outcome, GKE) |
| K8S-RBAC-001 negative controls | 12 (view, edit, GET, RoleBinding to cluster-admin, wrong roleRef kind, case near miss, malformed roleRef, no body, ClusterRole create, failed write, RequestReceived, GKE RoleBinding) |
| Generic / malformed | 10 (list/watch, delete, node update, non-Kubernetes GCP entry, empty object, bad objectRef, wrong kind, bad GKE request, bad request object) |
| K8S-EXEC-001 true positives | 6 (native create, get verb, unknown outcome, missing pod name, upper-case GKE method, and the relabeled GKE exec event) |
| K8S-EXEC-001 negative controls | 8 (403, GKE failed status, RequestReceived, pods/log, pods/attach, GET pod, malformed GKE method, non-core group) plus exec text inside a request body |
| K8S-SECRET-001 true positives | 7 (get with fake response data, list, watch, unknown outcome, GKE get, GKE list, and the relabeled metadata-only get) |
| K8S-SECRET-001 negative controls | 9 (create with fake data, update, delete, ConfigMap get, 403, RequestReceived, non-core `secrets`, malformed GKE method, malformed objectRef) |
| K8S-WORKLOAD-002 true positives | 12 (hostNetwork, hostPID, hostIPC, hostPath read-write and read-only, SYS_ADMIN, SYS_PTRACE, name normalization, init container, ephemeral container, GKE hostPID, and one event that fires both WORKLOAD rules) |
| K8S-WORKLOAD-002 negative controls | 14 (benign, flags false, string "true", numeric 1, unrelated capability, capability only in drop, non-hostPath volumes, malformed hostPath, malformed capabilities, Deployment out of scope, GET, failed create, RequestReceived, no request body) |

## History of relabeled events

Two events were labeled as unrelated when they were added, because no rule covered them yet.
They now have expected findings, and keep their `event_id` and the tag `formerly_unlabeled_generic`:

- `k8s-gen-gke-exec-into-pod` (GKE `pods.exec.create`) now expects K8S-EXEC-001.
- `k8s-gen-native-get-secret-metadata` (metadata-only Secret get) now expects K8S-SECRET-001.

## Fake sensitive values

Secret events include obviously fake `data`, password and key-looking strings so tests can prove they are
discarded. They cannot look like real credentials: the corpus scanner rejects real-looking token, key and
Secret string-data patterns, and the unit tests (not the corpus) cover the string-data field and token-shaped values.

## Semantics the corpus encodes

- Only a successful (2xx, or gRPC OK for GKE) or unknown-outcome write is a
  change event. A native event with a failing status becomes a generic event.
- Native events are actionable only at `ResponseComplete`, so one API request
  alerts once.
- `has_privileged_container` is `true`, `false` (body inspected) or unknown
  (body unavailable). Unknown never matches.
- A Deployment with a privileged or host-level template, a namespaced RoleBinding
  to cluster-admin, `pods/attach` and ClusterRole creation are deliberately outside
  the rules and are labeled with no expected finding. They are coverage boundaries,
  not passes.
- A denied `pods/exec` or Secret read (403, or a non-zero GKE status) is a generic
  event and does not alert.

## Rules for adding events

- Use fictional identifiers only: `example.com`, `system:serviceaccount:...`
  names, project `cloudshield-lab`, IPs from 192.0.2.0/24, 198.51.100.0/24 or
  203.0.113.0/24, and made-up UUIDs.
- Never add Secret data, tokens, kubeconfig material or keys. Loading fails if
  the scanner finds any.
- Update the counts in `manifest.yaml`.

Results computed on this corpus describe this corpus only, not production
accuracy.
