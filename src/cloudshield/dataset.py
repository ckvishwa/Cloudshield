"""Labeled offline audit-event corpus: loading and data-quality validation.

Each corpus line is an envelope. CloudShield-only metadata (provenance and
expected rule IDs) lives beside the raw telemetry, never inside it:

    {"event_id", "source_type", "source_reference", "parent_event_id",
     "expected_rules", "raw", "tags" (optional), "description" (optional)}
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Collection, Dict, List, Mapping, Optional, Tuple, Union

import yaml

from cloudshield.replay import parse_event_timestamp
from cloudshield.telemetry.file_ingest import load_events

SOURCE_OFFICIAL = "official_example"
SOURCE_PUBLIC = "public_sanitized_example"
SOURCE_SYNTHETIC = "synthetic_variant"
SOURCE_TYPES = (SOURCE_OFFICIAL, SOURCE_PUBLIC, SOURCE_SYNTHETIC)

CORPUS_FILE = "corpus.jsonl"
MANIFEST_FILE = "manifest.yaml"
TAG_INVALID_TIMESTAMP = "invalid_timestamp"  # the raw timestamp is deliberately malformed

_REQUIRED_KEYS = {"event_id", "source_type", "source_reference", "expected_rules", "raw"}
_OPTIONAL_KEYS = {"parent_event_id", "tags", "description"}

# Credential-like material that must never appear in a committed corpus.
_SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("OAuth access token prefix", re.compile(r"ya29\.")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("refresh_token", re.compile(r"refresh_token")),
    ("client_secret", re.compile(r"client_secret")),
    ("private_key field", re.compile(r"private_key")),
    ("accessToken field", re.compile(r"\baccessToken\b")),
    ("JWT-like token", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# RFC 5737 documentation ranges are the only IPv4 addresses allowed.
_DOC_IP_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")


class DatasetValidationError(ValueError):
    """The corpus failed data-quality validation (message lists every problem)."""


@dataclass(frozen=True)
class DatasetEvent:
    event_id: str
    source_type: str
    source_reference: str
    parent_event_id: Optional[str]
    expected_rules: Tuple[str, ...]
    raw: Dict[str, Any]
    tags: Tuple[str, ...] = ()
    description: str = ""


@dataclass(frozen=True)
class Dataset:
    events: List[DatasetEvent]
    manifest: Dict[str, Any] = field(default_factory=dict)


def _parse_envelope(obj: Mapping[str, Any], index: int) -> DatasetEvent:
    where = f"corpus event #{index}"
    missing = sorted(_REQUIRED_KEYS - set(obj))
    unknown = sorted(set(obj) - _REQUIRED_KEYS - _OPTIONAL_KEYS)
    if missing:
        raise DatasetValidationError(f"{where}: missing keys {missing}")
    if unknown:
        raise DatasetValidationError(f"{where}: unknown keys {unknown}")
    where = f"{where} ({obj['event_id']!r})"
    for key in ("event_id", "source_type", "source_reference"):
        if not isinstance(obj[key], str) or not obj[key].strip():
            raise DatasetValidationError(f"{where}: {key} must be a non-empty string")
    expected = obj["expected_rules"]
    if not isinstance(expected, list) or not all(isinstance(r, str) and r for r in expected):
        raise DatasetValidationError(f"{where}: expected_rules must be a list of rule ID strings")
    parent = obj.get("parent_event_id")
    if parent is not None and (not isinstance(parent, str) or not parent.strip()):
        raise DatasetValidationError(f"{where}: parent_event_id must be a non-empty string or null")
    tags = obj.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise DatasetValidationError(f"{where}: tags must be a list of strings")
    description = obj.get("description", "")
    if not isinstance(description, str):
        raise DatasetValidationError(f"{where}: description must be a string")
    if not isinstance(obj["raw"], dict):
        raise DatasetValidationError(f"{where}: raw must be a JSON object")
    return DatasetEvent(
        event_id=obj["event_id"],
        source_type=obj["source_type"],
        source_reference=obj["source_reference"],
        parent_event_id=parent,
        expected_rules=tuple(sorted(set(expected))),
        raw=obj["raw"],
        tags=tuple(tags),
        description=description,
    )


def find_sensitive_content(text: str) -> List[str]:
    """Credential-like strings, non-fictional emails and non-documentation IPs found in text."""
    problems = [label for label, pattern in _SECRET_PATTERNS if pattern.search(text)]
    for domain in sorted({m.group(1).lower() for m in _EMAIL_RE.finditer(text)}):
        if domain != "example.com" and not domain.endswith("gserviceaccount.com"):
            problems.append(f"email domain {domain!r} is not fictional (example.com / *.gserviceaccount.com)")
    for address in sorted(set(_IPV4_RE.findall(text))):
        if not address.startswith(_DOC_IP_PREFIXES):
            problems.append(f"IPv4 address {address} is outside the RFC 5737 documentation ranges")
    return problems


def validate_dataset(
    events: List[DatasetEvent],
    known_rule_ids: Collection[str],
    manifest: Optional[Mapping[str, Any]] = None,
) -> None:
    """Raise DatasetValidationError listing every data-quality problem found."""
    problems: List[str] = []
    known = set(known_rule_ids)
    by_id: Dict[str, DatasetEvent] = {}
    seen_raw: Dict[str, str] = {}

    for event in events:
        label = event.event_id
        if event.event_id in by_id:
            problems.append(f"{label}: duplicate event_id")
        by_id.setdefault(event.event_id, event)

        canonical = json.dumps(event.raw, sort_keys=True)
        if canonical in seen_raw:
            problems.append(f"{label}: raw event duplicates {seen_raw[canonical]}")
        seen_raw.setdefault(canonical, event.event_id)

        if event.source_type not in SOURCE_TYPES:
            problems.append(f"{label}: invalid source_type {event.source_type!r}")
        for rule_id in event.expected_rules:
            if rule_id not in known:
                problems.append(f"{label}: unknown rule ID {rule_id!r} in expected_rules")

        raw_timestamp = event.raw.get("timestamp")
        if TAG_INVALID_TIMESTAMP in event.tags:
            if raw_timestamp is None or parse_event_timestamp(raw_timestamp) is not None:
                problems.append(f"{label}: tagged {TAG_INVALID_TIMESTAMP} but the timestamp is not invalid")
        elif raw_timestamp is not None and parse_event_timestamp(raw_timestamp) is None:
            problems.append(f"{label}: invalid timestamp {raw_timestamp!r}")

        text = json.dumps({"raw": event.raw, "source_reference": event.source_reference,
                           "description": event.description, "tags": list(event.tags)})
        problems.extend(f"{label}: {problem}" for problem in find_sensitive_content(text))

    for event in events:
        parent = event.parent_event_id
        if event.source_type == SOURCE_SYNTHETIC:
            if parent is None:
                problems.append(f"{event.event_id}: synthetic_variant must reference parent_event_id")
            elif parent not in by_id:
                problems.append(f"{event.event_id}: parent_event_id {parent!r} not found in corpus")
            elif by_id[parent].source_type == SOURCE_SYNTHETIC:
                problems.append(f"{event.event_id}: parent {parent!r} must be a non-synthetic example")
        elif parent is not None:
            problems.append(f"{event.event_id}: only synthetic_variant events may have a parent_event_id")

    if manifest:
        declared = manifest.get("event_counts", {})
        actual = {t: sum(1 for e in events if e.source_type == t) for t in SOURCE_TYPES}
        actual["total"] = len(events)
        if declared != actual:
            problems.append(f"manifest event_counts {declared} do not match corpus {actual}")

    if problems:
        raise DatasetValidationError(
            f"{len(problems)} dataset problem(s):\n  - " + "\n  - ".join(problems)
        )


def load_dataset(dataset_dir: Union[str, Path], known_rule_ids: Collection[str]) -> Dataset:
    """Load and validate datasets/<name>/ (corpus.jsonl + manifest.yaml)."""
    root = Path(dataset_dir)
    manifest_path = root / MANIFEST_FILE
    if not manifest_path.is_file():
        raise DatasetValidationError(f"{manifest_path} not found")
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise DatasetValidationError(f"{manifest_path} must contain a mapping")

    raw_lines = load_events(root / CORPUS_FILE)
    events = [_parse_envelope(obj, index) for index, obj in enumerate(raw_lines, start=1)]
    validate_dataset(events, known_rule_ids, manifest)
    return Dataset(events=events, manifest=manifest)
