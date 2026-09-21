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

35 events: 8 `official_example`, 0 `public_sanitized_example`, 27
`synthetic_variant`. Synthetic events are authored for CloudShield and are not
real telemetry.

| Group | Events |
|-------|--------|
| GCP-IAM-001 true positives | 5 |
| GCP-IAM-001 negative controls | 5 (viewer, role removal, unrelated method, case near miss, missing optional fields) |
| GCP-IAM-001 known gap | 1 |
| GCP-IAM-002 true positives | 5, plus 1 boundary event with an invalid timestamp that must still fire |
| GCP-IAM-002 negative controls | 5 (approved caller, unprotected target, self-impersonation, missing principal, unknown method) |
| Official examples with no expected finding | 8 |
| Unrelated benign | 5 (four official, one synthetic) |
| Malformed / boundary | 5 |

## Known gap

`syn-iam001-gap-owner-without-deltas` grants `roles/owner` through a
`SetIamPolicy` entry shaped like the official example: it carries the resulting
policy in `response.bindings` but no `bindingDeltas`. GCP-IAM-001 works from
deltas and cannot tell what changed from the resulting policy alone, so it
misses this event. It is labeled as malicious on purpose, so replay reports it
as a false negative.

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
