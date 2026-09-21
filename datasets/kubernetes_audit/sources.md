# Sources

Access date for all external sources: 2026-09-21.

No complete official Kubernetes or GKE audit event was found that could be
copied, so **every event in `corpus.jsonl` is a `synthetic_variant`**. None is
real telemetry, and none is presented as an official example. Instead of a
`parent_event_id`, each event lists the documentation it was derived from in its
`derived_from` field. No credential, token, Secret data or personal identifier is
included.

## Kubernetes documentation

| Field | Value |
|-------|-------|
| Publisher | Kubernetes project (The Kubernetes Authors) |
| Pages | "kube-apiserver Audit Configuration (v1)" https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/ ; "Auditing" https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/ |
| Source type | `synthetic_variant` (structurally derived) |
| Fields/schema used | The audit `Event` field names (`apiVersion: audit.k8s.io/v1`, `kind: Event`, `level`, `auditID`, `stage`, `requestURI`, `verb`, `user.username`, `user.groups`, `impersonatedUser`, `sourceIPs`, `userAgent`, `objectRef`, `responseStatus.code`, `requestObject`, `requestReceivedTimestamp`, `stageTimestamp`, `annotations`) and the stage names (`RequestReceived`, `ResponseStarted`, `ResponseComplete`, `Panic`). |
| Handling | Read only. No text or sample was copied. Values (users, namespaces, IPs, UUIDs) are fictional. |

## Google GKE documentation

| Field | Value |
|-------|-------|
| Publisher | Google Cloud |
| Pages | "GKE audit logging information" https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging ; "Audit policy" https://cloud.google.com/kubernetes-engine/docs/concepts/audit-policy |
| Source type | `synthetic_variant` (structurally derived) |
| Fields/schema used | Query fields only: `resource.type = "k8s_cluster"`, `resource.labels.cluster_name` / `location`, `protoPayload.methodName` values such as `io.k8s.core.v1.pods.exec.*` and `io.k8s.authorization.rbac.v1.*`, `protoPayload.authenticationInfo.principalEmail`, `protoPayload.requestMetadata.callerIp`, `protoPayload.resourceName` in the `<group>/<version>/<resource>` form, and `protoPayload.request.metadata.name`. |
| Handling | Read only. The pages show queries, not complete log entries, so the GKE-wrapped events are authored, not copied. |

## Assumptions (not observed in real logs)

- The GKE `protoPayload.request` holds the Kubernetes object directly. The GKE
  documentation queries `protoPayload.request.metadata.name`, which supports
  this, but no full entry was seen.
- The exact `resourceName` layout for namespaced objects
  (`core/v1/namespaces/<ns>/pods/<name>`) and the mapping of `io.k8s.*` method
  prefixes to API groups are inferred from the documented examples.
- `protoPayload.status.code` is treated as a gRPC status (0 = OK). Whether GKE
  populates it for failed Kubernetes calls was not verified.
- Native events at `Request` level carry `requestObject`; at `Metadata` level
  they do not. That behavior comes from the Kubernetes audit documentation.
- A `pods/exec` request is modeled as verb `create` (or `get`) on the `exec`
  subresource with status 101 (Switching Protocols). The GKE method form
  `io.k8s.core.v1.pods.exec.*` comes from GKE's documented query; the native form and the
  status code are inferred and were not seen in real logs.
- Secret get/list/watch events are modeled at `Metadata` level (no bodies). Whether a
  given cluster's audit policy records them was not checked.

## Official and public sanitized examples

None are included.
