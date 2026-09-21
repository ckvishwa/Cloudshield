# Kubernetes / GKE audit corpus

A labeled corpus of Kubernetes audit telemetry for offline replay and
evaluation of CloudShield's Kubernetes detections. See `sources.md` for
provenance. All 51 events are `synthetic_variant`: authored for CloudShield from
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
| Generic / malformed | 12 (list/watch/get/delete, exec, node update, non-Kubernetes GCP entry, empty object, bad objectRef, wrong kind, bad GKE request, bad request object) |

## Semantics the corpus encodes

- Only a successful (2xx, or gRPC OK for GKE) or unknown-outcome write is a
  change event. A native event with a failing status becomes a generic event.
- Native events are actionable only at `ResponseComplete`, so one API request
  alerts once.
- `has_privileged_container` is `true`, `false` (body inspected) or unknown
  (body unavailable). Unknown never matches.
- A Deployment with a privileged template, a namespaced RoleBinding to
  cluster-admin, and `pods/exec` are deliberately outside these two rules and are
  labeled with no expected finding. They are coverage boundaries, not passes.

## Rules for adding events

- Use fictional identifiers only: `example.com`, `system:serviceaccount:...`
  names, project `cloudshield-lab`, IPs from 192.0.2.0/24, 198.51.100.0/24 or
  203.0.113.0/24, and made-up UUIDs.
- Never add Secret data, tokens, kubeconfig material or keys. Loading fails if
  the scanner finds any.
- Update the counts in `manifest.yaml`.

Results computed on this corpus describe this corpus only, not production
accuracy.
