"""Cloud Logging access: fetch real Cloud Audit Log entries as raw audit dicts.

This module only talks to the Cloud Logging API and converts entries into the
raw mapping shape that normalize_gcp_audit_event() expects. Normalization and
detection stay in gcp_audit.py and the engine. Authentication is Application
Default Credentials only; no credentials are accepted as arguments.
"""
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from cloudshield.config import validate_project_id

CREDENTIAL_GENERATION_METHODS = ("GenerateAccessToken", "GenerateIdToken", "SignJwt", "SignBlob")
IAM_CREDENTIALS_SERVICE = "iamcredentials.googleapis.com"
MAX_RESULTS_LIMIT = 1000
MAX_WINDOW_MINUTES = 1440

_ORDER_BY = {"asc": "timestamp asc", "desc": "timestamp desc"}

# Only these request keys are kept; everything else in `request`/`response`
# (payloads to sign, tokens, signatures) is dropped by design.
_SAFE_REQUEST_KEYS = ("name", "delegates", "scope", "lifetime", "audience", "includeEmail")
_SAFE_AUTH_KEYS = ("principalEmail", "principalSubject", "serviceAccountDelegationInfo")
_SAFE_METADATA_KEYS = ("callerIp", "callerSuppliedUserAgent")


class AuditLogError(Exception):
    """Base class for live audit-log retrieval failures."""


class AuditAuthenticationError(AuditLogError):
    """Application Default Credentials are missing, expired or rejected."""


class AuditPermissionDeniedError(AuditLogError):
    """The caller lacks permission to read logs (e.g. roles/logging.viewer)."""


class AuditApiDisabledError(AuditLogError):
    """The Cloud Logging API is not enabled for the project."""


class NoAuditLogsFoundError(AuditLogError):
    """The query succeeded but matched no entries."""


class AuditIngestionTimeoutError(AuditLogError):
    """Matching entries did not appear within the polling window."""


class MalformedAuditEntryError(AuditLogError, ValueError):
    """A log entry could not be converted into an audit dict."""


def build_credential_generation_filter(
    project_id: str,
    minutes: int,
    methods: Sequence[str] = CREDENTIAL_GENERATION_METHODS,
    now: Optional[datetime] = None,
) -> str:
    """Narrow Data Access filter for Service Account Credentials calls.

    The method-name match uses ':' (substring) so both 'GenerateAccessToken'
    and a fully qualified method name are found; the normalizer decides what
    actually counts. All interpolated values are validated or come from fixed
    lists, so the filter cannot be injected into.
    """
    validate_project_id(project_id)
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= MAX_WINDOW_MINUTES:
        raise ValueError(f"minutes must be an integer between 1 and {MAX_WINDOW_MINUTES}")
    if not methods:
        raise ValueError("methods must not be empty")
    unknown = [m for m in methods if m not in CREDENTIAL_GENERATION_METHODS]
    if unknown:
        raise ValueError(f"Unsupported credential-generation methods: {unknown}")

    since = (now or datetime.now(timezone.utc)) - timedelta(minutes=minutes)
    since_text = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    method_clause = " OR ".join(f'protoPayload.methodName:"{m}"' for m in methods)
    return (
        f'logName="projects/{project_id}/logs/cloudaudit.googleapis.com%2Fdata_access" '
        f'AND protoPayload.serviceName="{IAM_CREDENTIALS_SERVICE}" '
        f"AND ({method_clause}) "
        f'AND timestamp>="{since_text}"'
    )


def _plain(value: Any) -> Any:
    """Deep copy into plain dict/list/scalar types (never touches the original)."""
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _pick(source: Any, keys: Sequence[str]) -> Dict[str, Any]:
    if not isinstance(source, Mapping):
        return {}
    return {k: _plain(source[k]) for k in keys if k in source}


def entry_to_audit_dict(entry: Any) -> Dict[str, Any]:
    """Convert a Cloud Logging entry (or its API-repr mapping) to a raw audit dict.

    Works from the SDK's native API representation (``to_api_repr()``) and
    copies only a whitelist of security-relevant fields, so request/response
    bodies that could hold tokens, JWTs or signatures never leave this function.
    The input object is not modified.
    """
    if isinstance(entry, Mapping):
        resource = entry
    elif hasattr(entry, "to_api_repr"):
        try:
            resource = entry.to_api_repr()
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise MalformedAuditEntryError(f"Could not read log entry: {exc}") from exc
    else:
        raise MalformedAuditEntryError(f"Unsupported log entry type: {type(entry).__name__}")

    proto = resource.get("protoPayload") if isinstance(resource, Mapping) else None
    if not isinstance(proto, Mapping):
        raise MalformedAuditEntryError("Log entry has no protoPayload (not an audit log entry)")

    payload: Dict[str, Any] = {}
    for key in ("serviceName", "methodName", "resourceName"):
        if isinstance(proto.get(key), str):
            payload[key] = proto[key]
    payload["authenticationInfo"] = _pick(proto.get("authenticationInfo"), _SAFE_AUTH_KEYS)
    payload["requestMetadata"] = _pick(proto.get("requestMetadata"), _SAFE_METADATA_KEYS)
    payload["request"] = _pick(proto.get("request"), _SAFE_REQUEST_KEYS)
    for key in ("metadata", "serviceData"):  # IAM policy deltas (GCP-IAM-001)
        if isinstance(proto.get(key), Mapping):
            payload[key] = _plain(proto[key])

    result: Dict[str, Any] = {"protoPayload": payload}
    for key in ("timestamp", "logName", "insertId"):
        if isinstance(resource.get(key), str):
            result[key] = resource[key]
    monitored = resource.get("resource")
    if isinstance(monitored, Mapping):
        labels = monitored.get("labels")
        result["resource"] = {
            "type": monitored["type"] if isinstance(monitored.get("type"), str) else None,
            "labels": {str(k): v for k, v in labels.items() if isinstance(v, str)}
            if isinstance(labels, Mapping) else {},
        }
    return result


def _translate_google_error(exc: Exception) -> Optional[AuditLogError]:
    """Map Google client errors to actionable CloudShield errors; None if unknown."""
    from google.api_core import exceptions as api_exceptions
    from google.auth import exceptions as auth_exceptions

    if isinstance(exc, (auth_exceptions.DefaultCredentialsError, auth_exceptions.RefreshError,
                        api_exceptions.Unauthenticated)):
        return AuditAuthenticationError(
            "Application Default Credentials are missing or invalid. Run "
            "`gcloud auth application-default login` and retry."
        )
    if isinstance(exc, api_exceptions.PermissionDenied):
        text = str(exc)
        if "SERVICE_DISABLED" in text or "has not been used" in text or "is disabled" in text:
            return AuditApiDisabledError(
                "The Cloud Logging API is disabled for this project. Enable logging.googleapis.com."
            )
        return AuditPermissionDeniedError(
            "Permission denied reading Cloud Logging. The caller needs roles/logging.viewer "
            "(or roles/logging.privateLogViewer for Data Access logs) on the project."
        )
    return None


def fetch_audit_events(
    project_id: str,
    filter_: str,
    max_results: int,
    *,
    order: str = "asc",
    client: Any = None,
) -> List[Dict[str, Any]]:
    """Fetch at most max_results audit entries matching filter_ as raw audit dicts.

    order is 'asc' (oldest first, deterministic) or 'desc'. ``client`` exists so
    tests can inject a fake; by default a Cloud Logging client is created from
    Application Default Credentials.
    """
    validate_project_id(project_id)
    if not isinstance(filter_, str) or not filter_.strip():
        raise ValueError("filter_ must be a non-empty string")
    if isinstance(max_results, bool) or not isinstance(max_results, int) or not 1 <= max_results <= MAX_RESULTS_LIMIT:
        raise ValueError(f"max_results must be an integer between 1 and {MAX_RESULTS_LIMIT}")
    if order not in _ORDER_BY:
        raise ValueError(f"order must be one of {sorted(_ORDER_BY)}")

    try:
        if client is None:
            from google.cloud import logging as cloud_logging

            client = cloud_logging.Client(project=project_id)
        entries = client.list_entries(
            resource_names=[f"projects/{project_id}"],
            filter_=filter_,
            order_by=_ORDER_BY[order],
            max_results=max_results,
            page_size=min(max_results, 100),
        )
        events = []
        for entry in entries:
            events.append(entry_to_audit_dict(entry))
            if len(events) >= max_results:
                break
        return events
    except Exception as exc:  # translate known Google errors only; re-raise everything else
        translated = _translate_google_error(exc)
        if translated is None:
            raise
        raise translated from exc


def poll_audit_events(
    project_id: str,
    filter_: str,
    max_results: int,
    *,
    timeout_seconds: float = 300,
    interval_seconds: float = 10,
    predicate: Optional[Callable[[Dict[str, Any]], bool]] = None,
    fetch: Callable[..., List[Dict[str, Any]]] = fetch_audit_events,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> List[Dict[str, Any]]:
    """Poll until entries (optionally matching predicate) appear, or time out.

    Audit logs have ingestion latency, so one empty read is not a failure. The
    wait is bounded: timeout_seconds == 0 means a single attempt.
    """
    if timeout_seconds < 0 or interval_seconds <= 0:
        raise ValueError("timeout_seconds must be >= 0 and interval_seconds > 0")
    started = monotonic()
    deadline = started + timeout_seconds
    while True:
        events = fetch(project_id, filter_, max_results)
        matching = [e for e in events if predicate(e)] if predicate else events
        if matching:
            return matching
        remaining = deadline - monotonic()
        if remaining <= 0:
            if timeout_seconds == 0:
                raise NoAuditLogsFoundError("The query returned no matching audit entries")
            raise AuditIngestionTimeoutError(
                f"No matching audit entries appeared within {timeout_seconds:g}s "
                f"({len(events)} entries examined on the last poll)"
            )
        sleep(min(interval_seconds, remaining))


def redact_audit_dict(raw: Mapping[str, Any], replacements: Mapping[str, str]) -> Dict[str, Any]:
    """Copy of raw with every occurrence of each key replaced by its value.

    Used to build shareable fixtures from live entries. Raises if any original
    value survives, so a redaction gap is loud. insertId is always dropped.
    """
    if any(not original for original in replacements):
        raise ValueError("replacement keys must be non-empty strings")
    text = json.dumps(_plain(raw))
    # Longest first, so a project ID inside an email is not half-replaced.
    for original in sorted(replacements, key=len, reverse=True):
        text = text.replace(original, replacements[original])
    redacted = json.loads(text)
    redacted.pop("insertId", None)
    final_text = json.dumps(redacted)
    leftover = [
        o for o in replacements
        if o in final_text and not any(o in placeholder for placeholder in replacements.values())
    ]
    if leftover:
        raise ValueError("Redaction incomplete: original values still present")
    return redacted
