# Cloudshield

## Detections

| Rule ID | Title |
|---------|-------|
| GCP-IAM-001 | High-Risk IAM Role Granted |
| GCP-IAM-002 | Suspicious Service Account Credential Generation |

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
