import copy
import json
from datetime import datetime, timezone

import pytest
from google.api_core import exceptions as api_exceptions
from google.auth import exceptions as auth_exceptions
from google.cloud.audit import audit_log_pb2
from google.cloud.logging_v2.entries import ProtobufEntry
from google.cloud.logging_v2.resource import Resource

from cloudshield.engine.rule_binding import bind_service_account_impersonation_rule
from cloudshield.engine.rule_loader import load_rule
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
    entry_to_audit_dict,
    fetch_audit_events,
    poll_audit_events,
    redact_audit_dict,
)

PROJECT = "my-lab-project-1"
TARGET = f"prod-admin@{PROJECT}.iam.gserviceaccount.com"


def _payload(**overrides):
    payload = {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "serviceName": "iamcredentials.googleapis.com",
        "methodName": "GenerateAccessToken",
        "resourceName": "projects/-/serviceAccounts/1234567890",
        "authenticationInfo": {
            "principalEmail": "caller@example.com",
            "principalSubject": "user:caller@example.com",
            "serviceAccountDelegationInfo": [{"principalSubject": "user:orig@example.com"}],
            "authoritySelector": "not-needed",
        },
        "requestMetadata": {"callerIp": "198.51.100.9", "callerSuppliedUserAgent": "gcloud"},
        "request": {
            "name": f"projects/-/serviceAccounts/{TARGET}",
            "scope": ["https://www.googleapis.com/auth/cloud-platform"],
            "payload": "SECRET-PAYLOAD-TO-SIGN",
        },
        "response": {"accessToken": "ya29.SECRET-TOKEN", "signedJwt": "SECRET-JWT"},
        "authorizationInfo": [{"permission": "iam.serviceAccounts.getAccessToken"}],
    }
    payload.update(overrides)
    return payload


def _entry(payload=None, **kwargs):
    return ProtobufEntry(
        payload=_payload() if payload is None else payload,
        log_name=f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access",
        insert_id="insert-1",
        timestamp=datetime(2023, 10, 27, 12, 0, 0, tzinfo=timezone.utc),
        resource=Resource(type="service_account", labels={"email_id": TARGET, "project_id": PROJECT}),
        **kwargs,
    )


class FakeClient:
    def __init__(self, entries=(), error=None):
        self.entries = list(entries)
        self.error = error
        self.calls = []

    def list_entries(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return iter(self.entries)


# ---- entry conversion --------------------------------------------------------

def test_dict_payload_entry_converts_to_normalizable_audit_dict():
    raw = entry_to_audit_dict(_entry())
    event = normalize_gcp_audit_event(raw)

    assert event.event_type == "gcp.iam.service_account_credential_generation"
    assert event.principal == "caller@example.com"
    assert event.attributes["target_service_account"] == TARGET
    assert event.attributes["source_ip"] == "198.51.100.9"
    assert event.attributes["principal_subject"] == "user:caller@example.com"
    assert event.attributes["delegation_chain"] == ["user:orig@example.com"]
    assert event.timestamp.startswith("2023-10-27T12:00:00")
    assert raw["resource"]["labels"]["email_id"] == TARGET


def test_protobuf_message_payload_entry_converts():
    audit = audit_log_pb2.AuditLog()
    audit.service_name = "iamcredentials.googleapis.com"
    audit.method_name = "SignJwt"
    audit.authentication_info.principal_email = "caller@example.com"
    audit.request_metadata.caller_ip = "198.51.100.9"
    audit.request.update({"name": f"projects/-/serviceAccounts/{TARGET}"})

    raw = entry_to_audit_dict(_entry(payload=audit))
    event = normalize_gcp_audit_event(raw)

    assert event.attributes["credential_type"] == "signed_jwt"
    assert event.attributes["target_service_account"] == TARGET


def test_conversion_drops_tokens_and_unneeded_sections():
    raw = entry_to_audit_dict(_entry())
    rendered = json.dumps(raw)

    assert "SECRET" not in rendered
    assert "response" not in raw["protoPayload"]
    assert "authorizationInfo" not in raw["protoPayload"]
    assert "authoritySelector" not in rendered
    assert "payload" not in raw["protoPayload"]["request"]


def test_conversion_does_not_mutate_sdk_entry():
    entry = _entry()
    before = copy.deepcopy(entry.payload)
    entry_to_audit_dict(entry)

    assert entry.payload == before


def test_mapping_input_is_supported_and_not_mutated():
    api_repr = _entry().to_api_repr()
    before = copy.deepcopy(api_repr)

    assert entry_to_audit_dict(api_repr)["protoPayload"]["methodName"] == "GenerateAccessToken"
    assert api_repr == before


def test_iam_policy_deltas_are_preserved_for_iam_001():
    payload = _payload(
        serviceName="iam.googleapis.com", methodName="SetIamPolicy",
        metadata={"bindingDeltas": [{"action": "ADD", "role": "roles/owner", "member": "user:x@example.com"}]},
    )
    event = normalize_gcp_audit_event(entry_to_audit_dict(_entry(payload=payload)))

    assert event.attributes["roles_added"] == ["roles/owner"]


def test_entry_without_proto_payload_is_rejected():
    with pytest.raises(MalformedAuditEntryError, match="protoPayload"):
        entry_to_audit_dict({"textPayload": "hello", "timestamp": "2023-10-27T12:00:00Z"})
    with pytest.raises(MalformedAuditEntryError):
        entry_to_audit_dict({"protoPayload": None})


@pytest.mark.parametrize("bad", [None, 42, "string", object(), ["protoPayload"]])
def test_malformed_entry_objects_are_rejected(bad):
    with pytest.raises(MalformedAuditEntryError):
        entry_to_audit_dict(bad)


def test_entry_whose_to_api_repr_fails_is_rejected():
    class Broken:
        def to_api_repr(self):
            raise KeyError("boom")

    with pytest.raises(MalformedAuditEntryError, match="Could not read"):
        entry_to_audit_dict(Broken())


def test_odd_field_types_are_tolerated():
    raw = entry_to_audit_dict({"protoPayload": {
        "serviceName": 5, "authenticationInfo": "x", "requestMetadata": [], "request": "y",
        "metadata": "z",
    }, "resource": {"labels": "nope"}, "timestamp": 3})

    assert normalize_gcp_audit_event(raw).event_type == "gcp.audit.generic"


# ---- filter ------------------------------------------------------------------

def test_filter_is_narrow_and_time_bounded():
    now = datetime(2023, 10, 27, 12, 0, 0, tzinfo=timezone.utc)
    filter_ = build_credential_generation_filter(PROJECT, 30, now=now)

    assert f'logName="projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access"' in filter_
    assert 'protoPayload.serviceName="iamcredentials.googleapis.com"' in filter_
    for method in ("GenerateAccessToken", "GenerateIdToken", "SignJwt", "SignBlob"):
        assert f'protoPayload.methodName:"{method}"' in filter_
    assert 'timestamp>="2023-10-27T11:30:00Z"' in filter_


@pytest.mark.parametrize("kwargs", [
    {"project_id": 'p" OR 1=1'}, {"project_id": "BAD"}, {"minutes": 0}, {"minutes": 100000},
    {"minutes": True}, {"minutes": 1.5}, {"methods": []}, {"methods": ["DeleteEverything"]},
])
def test_filter_rejects_unsafe_input(kwargs):
    params = {"project_id": PROJECT, "minutes": 30}
    params.update(kwargs)

    with pytest.raises(ValueError):
        build_credential_generation_filter(**params)


# ---- fetch -------------------------------------------------------------------

def test_fetch_passes_filter_project_order_and_bound_to_client():
    client = FakeClient([_entry()])
    events = fetch_audit_events(PROJECT, "my-filter", 5, order="desc", client=client)

    (call,) = client.calls
    assert call["filter_"] == "my-filter"
    assert call["resource_names"] == [f"projects/{PROJECT}"]
    assert call["order_by"] == "timestamp desc"
    assert call["max_results"] == 5
    assert len(events) == 1


def test_fetch_default_order_is_ascending():
    client = FakeClient()
    fetch_audit_events(PROJECT, "f", 5, client=client)

    assert client.calls[0]["order_by"] == "timestamp asc"


def test_fetch_enforces_max_results_even_if_client_returns_more():
    client = FakeClient([_entry() for _ in range(10)])

    assert len(fetch_audit_events(PROJECT, "f", 3, client=client)) == 3


@pytest.mark.parametrize("max_results", [0, -1, 1001, True, "5", 2.5])
def test_fetch_rejects_unbounded_or_invalid_max_results(max_results):
    with pytest.raises(ValueError, match="max_results"):
        fetch_audit_events(PROJECT, "f", max_results, client=FakeClient())


def test_fetch_rejects_bad_arguments():
    with pytest.raises(ValueError):
        fetch_audit_events("BAD", "f", 5, client=FakeClient())
    with pytest.raises(ValueError):
        fetch_audit_events(PROJECT, "  ", 5, client=FakeClient())
    with pytest.raises(ValueError):
        fetch_audit_events(PROJECT, "f", 5, order="sideways", client=FakeClient())


def test_fetch_propagates_malformed_entries():
    client = FakeClient([_entry(), {"textPayload": "not audit"}])

    with pytest.raises(MalformedAuditEntryError):
        fetch_audit_events(PROJECT, "f", 5, client=client)


@pytest.mark.parametrize("error,expected", [
    (auth_exceptions.DefaultCredentialsError("no creds"), AuditAuthenticationError),
    (auth_exceptions.RefreshError("expired"), AuditAuthenticationError),
    (api_exceptions.Unauthenticated("nope"), AuditAuthenticationError),
    (api_exceptions.PermissionDenied("caller lacks logging.logEntries.list"), AuditPermissionDeniedError),
    (api_exceptions.PermissionDenied("Cloud Logging API has not been used in project 1 before"),
     AuditApiDisabledError),
    (api_exceptions.PermissionDenied("reason: SERVICE_DISABLED"), AuditApiDisabledError),
])
def test_fetch_translates_known_google_errors(error, expected):
    with pytest.raises(expected):
        fetch_audit_events(PROJECT, "f", 5, client=FakeClient(error=error))


def test_fetch_does_not_swallow_unknown_errors():
    with pytest.raises(RuntimeError, match="unexpected"):
        fetch_audit_events(PROJECT, "f", 5, client=FakeClient(error=RuntimeError("unexpected")))
    with pytest.raises(api_exceptions.ServiceUnavailable):
        fetch_audit_events(PROJECT, "f", 5, client=FakeClient(error=api_exceptions.ServiceUnavailable("down")))


# ---- polling -----------------------------------------------------------------

class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _poll(fetch, clock, **kwargs):
    return poll_audit_events(PROJECT, "f", 5, fetch=fetch, sleep=clock.sleep,
                             monotonic=clock.monotonic, **kwargs)


def test_poll_returns_as_soon_as_entries_appear():
    clock = Clock()
    results = [[], [], [{"id": 1}]]

    def fetch(project_id, filter_, max_results):
        return results.pop(0)

    assert _poll(fetch, clock, timeout_seconds=300, interval_seconds=10) == [{"id": 1}]
    assert clock.sleeps == [10, 10]


def test_poll_times_out_with_bounded_attempts():
    clock = Clock()
    calls = []

    def fetch(project_id, filter_, max_results):
        calls.append(1)
        return []

    with pytest.raises(AuditIngestionTimeoutError, match="within 30s"):
        _poll(fetch, clock, timeout_seconds=30, interval_seconds=10)

    assert len(calls) == 4
    assert clock.now == 30


def test_poll_single_attempt_reports_no_logs_found():
    clock = Clock()

    with pytest.raises(NoAuditLogsFoundError):
        _poll(lambda *a: [], clock, timeout_seconds=0)

    assert clock.sleeps == []


def test_poll_predicate_filters_entries():
    clock = Clock()
    fetch = lambda *a: [{"k": "other"}, {"k": "wanted"}]

    assert _poll(fetch, clock, timeout_seconds=0, predicate=lambda e: e["k"] == "wanted") == [{"k": "wanted"}]


def test_poll_rejects_bad_timing():
    with pytest.raises(ValueError):
        _poll(lambda *a: [], Clock(), timeout_seconds=-1)
    with pytest.raises(ValueError):
        _poll(lambda *a: [], Clock(), interval_seconds=0)


# ---- redaction ---------------------------------------------------------------

def test_redact_replaces_identifiers_and_drops_insert_id():
    raw = entry_to_audit_dict(_entry())
    redacted = redact_audit_dict(raw, {
        PROJECT: "cloudshield-lab",
        "caller@example.com": "developer@example.com",
        "198.51.100.9": "203.0.113.10",
    })
    text = json.dumps(redacted)

    assert PROJECT not in text and "caller@example.com" not in text and "198.51.100.9" not in text
    assert "prod-admin@cloudshield-lab.iam.gserviceaccount.com" in text
    assert "insertId" not in redacted
    assert raw["insertId"] == "insert-1"


def test_redact_rejects_empty_keys():
    with pytest.raises(ValueError):
        redact_audit_dict({"a": "b"}, {"": "x"})


# ---- live path with a runtime-bound rule ------------------------------------

def test_converted_entry_fires_bound_rule_and_not_the_unbound_example():
    import os
    rule = load_rule(os.path.join(os.path.dirname(__file__), "..", "rules", "iam",
                                  "service_account_impersonation.yaml"))
    event = normalize_gcp_audit_event(entry_to_audit_dict(_entry()))

    assert run_event(event, [rule]) == []  # committed example rule targets cloudshield-lab
    (finding,) = run_event(event, [bind_service_account_impersonation_rule(rule, PROJECT)])
    assert finding.rule_id == "GCP-IAM-002"
    assert finding.principal == "caller@example.com"
