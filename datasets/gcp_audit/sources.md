# Sources

Access date for all external sources: 2026-09-21.

Every event in `corpus.jsonl` carries `source_type`, `source_reference` and (for
variants) `parent_event_id`. Nothing here is real production telemetry, and no
credential, token, private key or personal identifier is included.

## Google Cloud documentation (official examples)

| Field | Value |
|-------|-------|
| Publisher | Google Cloud |
| Page | IAM: "Example logs for service accounts" — https://cloud.google.com/iam/docs/audit-logging/examples-service-accounts |
| Source type | `official_example` |
| Fields/schema used | `logName`, `protoPayload.{serviceName, methodName, authenticationInfo (principalEmail, serviceAccountDelegationInfo.firstPartyPrincipal), request, response, resourceName}`, `resource.{type, labels}` |
| Handling | Copied as published, with these changes: valid JSON (the page has stray trailing commas in one sample); `request.project_number` in the actAs sample replaced with zeros. Values such as `my-project` and `example-user@example.com` are the documentation's own placeholders. |

Events: `off-sa-generate-access-token`, `off-sa-set-iam-policy-on-sa`,
`off-project-set-iam-policy`, `off-create-service-account`, `off-actas`,
`off-pubsub-create-topic-delegation`, `off-create-sa-key`.

| Field | Value |
|-------|-------|
| Publisher | Google Cloud |
| Page | Cloud Logging: "Understand audit logs" — https://cloud.google.com/logging/docs/audit/understanding-audit-logs |
| Source type | `official_example` |
| Fields/schema used | `protoPayload.serviceData.policyDelta.bindingDeltas[{action, role, member}]` |
| Handling | The page shows this example in an abbreviated, non-JSON notation with elided (`[...]`) parts. It was reformatted into valid JSON and the elided parts were omitted. |

Event: `off-appengine-set-iam-policy-delta`.

## Structural references (for synthetic variants)

| Field | Value |
|-------|-------|
| Publisher | Google Cloud |
| Pages | https://cloud.google.com/iam/docs/audit-logging/audit-logging-iamcreds (Service Account Credentials audit logging: method names and log types) |
| Source type | `synthetic_variant` (structurally derived) |
| Handling | Read for method names and which log type carries them. No text or samples were copied. |

## Synthetic variants

27 events authored for CloudShield. Each names an official event as its
`parent_event_id`, from which its log envelope or field layout is derived. They
use fictional identifiers only: `example.com` users, the fictional project
`cloudshield-lab`, and RFC 5737 documentation IPs (`203.0.113.x`).

Two shapes are assumptions rather than observed samples:

- `metadata.bindingDeltas` as an alternative location for IAM binding deltas.
- A fully qualified iamcredentials method name
  (`google.iam.credentials.v1.IAMCredentials.SignBlob`); the official sample
  uses the bare method name.

## Public sanitized examples

None are included.
