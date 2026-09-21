"""Telemetry adapters: which normalizer (and timestamp accessor) a dataset uses.

A dataset declares ``telemetry_type`` in its manifest; consumers look the
adapter up here instead of branching on the type.
"""
from dataclasses import dataclass
from typing import Any, Callable, Dict

from cloudshield.models import NormalizedEvent
from cloudshield.telemetry.gcp_audit import normalize_gcp_audit_event
from cloudshield.telemetry.kubernetes_audit import kubernetes_raw_timestamp, normalize_kubernetes_audit_event


@dataclass(frozen=True)
class TelemetryAdapter:
    normalize: Callable[[Any], NormalizedEvent]
    timestamp_of: Callable[[Any], Any]  # raw timestamp value used for replay pacing and validation


def _gcp_timestamp(raw: Any) -> Any:
    return raw.get("timestamp") if isinstance(raw, dict) else None


ADAPTERS: Dict[str, TelemetryAdapter] = {
    "gcp_audit": TelemetryAdapter(normalize_gcp_audit_event, _gcp_timestamp),
    "kubernetes_audit": TelemetryAdapter(normalize_kubernetes_audit_event, kubernetes_raw_timestamp),
}


def get_adapter(telemetry_type: str) -> TelemetryAdapter:
    try:
        return ADAPTERS[telemetry_type]
    except (KeyError, TypeError):
        raise ValueError(f"Unknown telemetry_type {telemetry_type!r}; supported: {sorted(ADAPTERS)}") from None
