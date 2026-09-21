# GCP audit corpus

A labeled corpus of GCP Cloud Audit Log events for offline replay and
evaluation of CloudShield detections. See `sources.md` for provenance.

- `corpus.jsonl`: one envelope per line: `event_id`, `source_type`,
  `source_reference`, `parent_event_id`, `expected_rules`, `raw`, optional
  `tags` and `description`. The `raw` object is telemetry only; labels are never
  placed inside it.
- `manifest.yaml`: dataset metadata and the expected event counts (checked on load).
- `sources.md`: where every event came from.

## Composition

49 events: 8 `official_example`, 0 `public_sanitized_example`, 41
`synthetic_variant`. Synthetic events are authored for CloudShield and are not
real telemetry.

| Group | Events |
|-------|--------|
| GCP-IAM-001 true positives | 5 |
| GCP-IAM-001 negative controls | 5 (viewer, role removal, unrelated method, case near miss, missing optional fields) |
| GCP-IAM-002 true positives | 5, plus 1 boundary event with an invalid timestamp that must still fire |
| GCP-IAM-002 negative controls | 5 (approved caller, unprotected target, self-impersonation, missing principal, unknown method) |
| GCP-IAM-003 true positives (policy snapshot, no delta) | 7: the relabeled former gap event, four more roles, a mixed-members event and a request-policy fallback |
| GCP-IAM-003 negative controls | 7 (viewer only, custom role, malformed snapshot, unrelated method with `response.bindings`, no policy information, request-policy viewer, response preferred over request) |
| Delta plus snapshot | 1: expected GCP-IAM-001 only, GCP-IAM-003 must stay silent |
| Official examples with no expected finding | 8 |
| Unrelated benign | 5 (four official, one synthetic) |
| Malformed / boundary | 5 |

## History: the former GCP-IAM-001 gap

`syn-iam001-gap-owner-without-deltas` was added when the corpus was first
built. It has the shape of Google's official project `SetIamPolicy` example: the
resulting policy is in `response.bindings` and there are no `bindingDeltas`. It
contains `roles/owner`. GCP-IAM-001 needs an ADD delta, so it missed the event,
and the event was labeled GCP-IAM-001 to record that as a false negative.

That label was wrong in principle: a policy snapshot containing `roles/owner`
does not prove the role was newly granted. GCP-IAM-001 means a confirmed grant
and was left unchanged. The event is now labeled **GCP-IAM-003**, a separate,
lower-confidence rule for "a high-risk role is present in the resulting policy
and no delta is available". The event keeps its original `event_id` and carries
the tag `formerly_iam001_known_gap` so the history stays visible. Nothing here
claims the role was newly granted.

## Rules for adding events

- Use only fictional identifiers: `example.com`, `*.gserviceaccount.com`,
  project `cloudshield-lab`, IPs from 192.0.2.0/24, 198.51.100.0/24 or
  203.0.113.0/24.
- Never add tokens, keys, signatures or real accounts. Loading fails if the
  scanner finds any.
- Synthetic events must name a non-synthetic `parent_event_id`.
- Update the counts in `manifest.yaml`.

Results computed on this corpus describe this corpus only. They are not
production accuracy figures.
