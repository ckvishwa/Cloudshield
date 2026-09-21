"""Run the GCP-IAM-002 detection against real Cloud Audit Log entries.

Read-only: it queries Cloud Logging with Application Default Credentials
(`gcloud auth application-default login`). It never creates credentials, never
prints or stores request/response bodies, and only writes a file when
--dump-sanitized is given (redacted first).

Exit codes: 0 finding(s), 2 entries found but no finding, 3 no entries /
timeout, 4 auth/permission/API error, 5 malformed entry, 1 usage error.
"""
import argparse
import dataclasses
import json
import sys
from pathlib import Path

from cloudshield.engine.rule_binding import bind_service_account_impersonation_rule
from cloudshield.engine.rule_loader import load_rules
from cloudshield.engine.runner import run_event
from cloudshield.telemetry.gcp_audit import normalize_gcp_audit_event
from cloudshield.telemetry.gcp_logging import (
    AuditApiDisabledError,
    AuditAuthenticationError,
    AuditIngestionTimeoutError,
    AuditPermissionDeniedError,
    MalformedAuditEntryError,
    NoAuditLogsFoundError,
    build_credential_generation_filter,
    poll_audit_events,
    redact_audit_dict,
)

REPO_RULES = Path(__file__).resolve().parent.parent / "rules"


def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--minutes", type=int, default=30, help="look-back window (default 30)")
    parser.add_argument("--max-results", type=int, default=50, help="entry cap (default 50)")
    parser.add_argument("--wait-seconds", type=int, default=0,
                        help="poll up to this long for entries to appear (default: single attempt)")
    parser.add_argument("--rules-dir", default=str(REPO_RULES))
    parser.add_argument("--dump-sanitized", metavar="PATH",
                        help="write the first matching entry, redacted, to PATH")
    return parser.parse_args(argv)


def _redactions(raw):
    """Placeholders for identifiers in one live entry (project, caller, IP, SA id)."""
    payload = raw.get("protoPayload", {})
    labels = (raw.get("resource") or {}).get("labels", {})
    project = raw["logName"].split("/")[1] if raw.get("logName", "").startswith("projects/") else None
    values = {
        project: "cloudshield-lab",
        payload.get("authenticationInfo", {}).get("principalEmail"): "developer@example.com",
        payload.get("requestMetadata", {}).get("callerIp"): "203.0.113.10",
        labels.get("unique_id"): "000000000000000000000",
    }
    return {k: v for k, v in values.items() if k}


def main(argv=None):
    args = _parse_args(argv)
    try:
        filter_ = build_credential_generation_filter(args.project, args.minutes)
        raw_events = poll_audit_events(
            args.project, filter_, args.max_results,
            timeout_seconds=args.wait_seconds, interval_seconds=10,
        )
    except ValueError as exc:
        if isinstance(exc, MalformedAuditEntryError):
            print(f"Malformed audit entry: {exc}", file=sys.stderr)
            return 5
        print(f"Invalid argument: {exc}", file=sys.stderr)
        return 1
    except (AuditAuthenticationError, AuditPermissionDeniedError, AuditApiDisabledError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 4
    except (NoAuditLogsFoundError, AuditIngestionTimeoutError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 3

    rules = [
        bind_service_account_impersonation_rule(r, args.project) if r.rule_id == "GCP-IAM-002" else r
        for r in load_rules(args.rules_dir)
    ]
    findings = []
    for raw in raw_events:
        findings.extend(run_event(normalize_gcp_audit_event(raw), rules))

    print(f"entries examined: {len(raw_events)}; findings: {len(findings)}")
    for finding in findings:
        print(json.dumps(dataclasses.asdict(finding), indent=2, default=str))

    if args.dump_sanitized:
        redacted = redact_audit_dict(raw_events[0], _redactions(raw_events[0]))
        Path(args.dump_sanitized).write_text(json.dumps(redacted, indent=2) + "\n", encoding="utf-8")
        print(f"sanitized entry written to {args.dump_sanitized}")
    return 0 if findings else 2


if __name__ == "__main__":
    sys.exit(main())
