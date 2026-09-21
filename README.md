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

## GCP Lab Infrastructure

Terraform (`terraform/`) defines the GCP lab that future real Cloud Audit Logs
will come from:

- required APIs: cloudresourcemanager, compute, iam, iamcredentials, logging, serviceusage
- custom-mode VPC `cloudshield-vpc` with one private subnet (`10.20.0.0/24`) and no firewall rules
- service accounts `prod-admin` (protected), `ci-deployer` (approved caller), `app-runtime`; no keys, no project roles
- impersonation lab foundation: `roles/iam.serviceAccountTokenCreator` scoped to the single `prod-admin` service account
- Cloud Audit Log ingestion is planned next

**Status: Terraform validation completed (`fmt`, `init`, `validate`). Nothing has been applied; no GCP resources exist yet.**

```
cd terraform
cp terraform.tfvars.example terraform.tfvars   # git-ignored; set project_id
terraform init && terraform validate
```

See `docs/architecture.md` for details and the security notes.
