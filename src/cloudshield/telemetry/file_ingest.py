"""Load raw telemetry events from JSON / JSONL files.

Offline source of raw event dictionaries, feeding the same normalizers as the
live Cloud Logging backend. Standard library only.

Format rules:
- ``.jsonl`` / ``.ndjson``: one JSON object per line. Blank lines are skipped
  (line numbers in errors still refer to the physical line).
- ``.json``: a single JSON object (one event) or an array of JSON objects.
  Any other top-level value, or a non-object array element, is rejected.
- Files are UTF-8 (a leading BOM is tolerated). An empty file yields ``[]``.
- Events are returned in file order; the loader never mutates or reorders them.
- ``max_events`` is a hard safety cap: a file with more events raises instead
  of being silently truncated.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Union

DEFAULT_MAX_EVENTS = 100_000
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
JSONL_SUFFIXES = (".jsonl", ".ndjson")
JSON_SUFFIXES = (".json",)


class IngestError(ValueError):
    """A telemetry file could not be read or parsed."""


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _read_text(path: Path, max_bytes: int) -> str:
    size = path.stat().st_size
    if size > max_bytes:
        raise IngestError(f"{path}: file is {size} bytes, over the {max_bytes} byte limit")
    try:
        return path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError(f"{path}: not valid UTF-8 ({exc.reason} at byte {exc.start})") from exc


def _loads(text: str, where: str) -> Any:
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise IngestError(f"{where}: invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})") from exc
    except ValueError as exc:
        raise IngestError(f"{where}: invalid JSON: {exc}") from exc


def _require_object(value: Any, where: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise IngestError(f"{where}: expected a JSON object, got {type(value).__name__}")
    return value


def _check_cap(count: int, max_events: int, path: Path) -> None:
    if count > max_events:
        raise IngestError(f"{path}: more than {max_events} events (max_events cap)")


def _load_jsonl(path: Path, text: str, max_events: int) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        where = f"{path}: line {line_number}"
        events.append(_require_object(_loads(line, where), where))
        _check_cap(len(events), max_events, path)
    return events


def _load_json(path: Path, text: str, max_events: int) -> List[Dict[str, Any]]:
    if not text.strip():
        return []
    document = _loads(text, str(path))
    if isinstance(document, dict):
        return [document]
    if not isinstance(document, list):
        raise IngestError(f"{path}: top-level JSON must be an object or an array of objects, "
                          f"got {type(document).__name__}")
    _check_cap(len(document), max_events, path)
    return [_require_object(item, f"{path}: element {index}") for index, item in enumerate(document)]


def load_events(
    path: Union[str, Path],
    *,
    max_events: int = DEFAULT_MAX_EVENTS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> List[Dict[str, Any]]:
    """Load raw event objects from a .json / .jsonl / .ndjson file."""
    if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
        raise ValueError("max_events must be a positive integer")
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    if suffix not in JSONL_SUFFIXES + JSON_SUFFIXES:
        raise IngestError(f"{file_path}: unsupported file type {suffix!r} (use .json, .jsonl or .ndjson)")
    text = _read_text(file_path, max_bytes)
    if suffix in JSONL_SUFFIXES:
        return _load_jsonl(file_path, text, max_events)
    return _load_json(file_path, text, max_events)
