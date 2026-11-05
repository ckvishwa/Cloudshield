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
  of being silently truncated. It is enforced while parsing (array elements and
  lines are decoded one at a time), so a file of many tiny events is rejected
  without first building every event.
- JSONL lines are split on ``\n`` only (a trailing ``\r`` is dropped), so U+2028 /
  U+2029 inside a JSON string are kept, as JSON allows.
- Pathologically nested JSON is an ``IngestError``, never a ``RecursionError``.
"""
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple, Union

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


_WHITESPACE = " \t\n\r"
_DECODER = json.JSONDecoder(parse_constant=_reject_constant)


def _decode_at(text: str, index: int, where: str) -> Tuple[Any, int]:
    """Decode one JSON value starting at ``index``; every failure is an IngestError."""
    try:
        return _DECODER.raw_decode(text, index)
    except json.JSONDecodeError as exc:
        raise IngestError(f"{where}: invalid JSON: {exc.msg} (line {exc.lineno}, column {exc.colno})") from exc
    except RecursionError as exc:
        raise IngestError(f"{where}: invalid JSON: nested too deeply") from exc
    except ValueError as exc:
        raise IngestError(f"{where}: invalid JSON: {exc}") from exc


def _skip_ws(text: str, index: int) -> int:
    while index < len(text) and text[index] in _WHITESPACE:
        index += 1
    return index


def _trailing_data_error(text: str, index: int, where: str) -> IngestError:
    line = text.count("\n", 0, index) + 1
    column = index - (text.rfind("\n", 0, index) + 1) + 1
    return IngestError(f"{where}: invalid JSON: Extra data (line {line}, column {column})")


def _loads(text: str, where: str) -> Any:
    start = _skip_ws(text, 0)
    value, end = _decode_at(text, start, where)
    end = _skip_ws(text, end)
    if end != len(text):
        raise _trailing_data_error(text, end, where)
    return value


def _require_object(value: Any, where: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise IngestError(f"{where}: expected a JSON object, got {type(value).__name__}")
    return value


def _check_cap(count: int, max_events: int, path: Path) -> None:
    if count > max_events:
        raise IngestError(f"{path}: more than {max_events} events (max_events cap)")


def _iter_lines(text: str) -> Iterator[str]:
    """Physical lines split on \\n only, lazily (no list of every line)."""
    start = 0
    while start < len(text):
        end = text.find("\n", start)
        if end == -1:
            end = len(text)
        line = text[start:end]
        yield line[:-1] if line.endswith("\r") else line
        start = end + 1


def _iter_array(text: str, start: int, path: Path) -> Iterator[Tuple[int, Any]]:
    """Yield (index, element) of the top-level array opening at ``start``, one at a time."""
    where = str(path)
    index = _skip_ws(text, start + 1)
    if index < len(text) and text[index] == "]":
        index += 1
    else:
        position = 0
        while True:
            value, index = _decode_at(text, index, where)
            yield position, value
            position += 1
            index = _skip_ws(text, index)
            if index < len(text) and text[index] == ",":
                index = _skip_ws(text, index + 1)
                continue
            if index < len(text) and text[index] == "]":
                index += 1
                break
            raise IngestError(f"{where}: invalid JSON: expected ',' or ']' after element {position - 1}")
    index = _skip_ws(text, index)
    if index != len(text):
        raise _trailing_data_error(text, index, where)


def _load_jsonl(path: Path, text: str, max_events: int) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for line_number, line in enumerate(_iter_lines(text), start=1):
        if not line.strip():
            continue
        where = f"{path}: line {line_number}"
        events.append(_require_object(_loads(line, where), where))
        _check_cap(len(events), max_events, path)
    return events


def _load_json(path: Path, text: str, max_events: int) -> List[Dict[str, Any]]:
    start = _skip_ws(text, 0)
    if start == len(text):
        return []
    if text[start] == "[":
        events: List[Dict[str, Any]] = []
        for index, item in _iter_array(text, start, path):
            _check_cap(index + 1, max_events, path)
            events.append(_require_object(item, f"{path}: element {index}"))
        return events
    document = _loads(text, str(path))
    if isinstance(document, dict):
        return [document]
    raise IngestError(f"{path}: top-level JSON must be an object or an array of objects, "
                      f"got {type(document).__name__}")


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
