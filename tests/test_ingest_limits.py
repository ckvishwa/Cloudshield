"""Regression tests: ingestion limits apply before expensive allocation, and
hostile JSON fails as IngestError (the error callers handle), never as a crash."""
import tracemalloc

import pytest

from cloudshield.telemetry.file_ingest import IngestError, load_events


@pytest.mark.parametrize("name", ["deep.json", "deep.jsonl"])
def test_deeply_nested_json_is_an_ingest_error(tmp_path, name):
    path = tmp_path / name
    path.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    with pytest.raises(IngestError, match="nested too deeply"):
        load_events(path)


def test_deep_nesting_inside_an_array_element_is_an_ingest_error(tmp_path):
    path = tmp_path / "deep_element.json"
    path.write_text('[{"a": ' + "[" * 200_000 + "]" * 200_000 + "}]", encoding="utf-8")
    with pytest.raises(IngestError, match="nested too deeply"):
        load_events(path)


def _peak_bytes_while_rejecting(path, max_events):
    tracemalloc.start()
    try:
        with pytest.raises(IngestError, match=f"more than {max_events} events"):
            load_events(path, max_events=max_events)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("name, body", [
    ("many.json", "[" + ",".join(["{}"] * 500_000) + "]"),
    ("many.jsonl", "{}\n" * 500_000),
])
def test_event_cap_rejects_before_materializing_the_whole_file(tmp_path, name, body):
    """A 1.5 MB file of tiny events with a cap of 10 must be rejected without
    building every event (or every line) first. Previously the peak was 25-40x
    the file size; the bound here is the file text itself plus small overhead."""
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    size = path.stat().st_size
    assert _peak_bytes_while_rejecting(path, 10) < 3 * size


def test_jsonl_line_may_contain_unicode_line_separators(tmp_path):
    """U+2028/U+2029 are legal inside a JSON string; JSONL splits on \\n only."""
    path = tmp_path / "seps.jsonl"
    path.write_text('{"a": "x y"}\n{"b": "p q"}\n', encoding="utf-8")
    assert load_events(path) == [{"a": "x y"}, {"b": "p q"}]


def test_jsonl_crlf_and_physical_line_numbers_are_kept(tmp_path):
    path = tmp_path / "crlf.jsonl"
    path.write_bytes(b'{"a": 1}\r\n\r\n{"b": 2}\r\n{oops\r\n')
    with pytest.raises(IngestError, match="line 4"):
        load_events(path)
    path.write_bytes(b'{"a": 1}\r\n\r\n{"b": 2}\r\n')
    assert load_events(path) == [{"a": 1}, {"b": 2}]


@pytest.mark.parametrize("body, fragment", [
    ("[{}, {}", "invalid JSON"),
    ("[{},]", "invalid JSON"),
    ("[{}] [{}]", "invalid JSON"),
    ("[{}, 3]", "element 1"),
    ("[ ]", None),
    ('  [ {"a": 1} ,{"b": [2]} ]  ', None),
])
def test_array_documents_still_parse_strictly(tmp_path, body, fragment):
    path = tmp_path / "arr.json"
    path.write_text(body, encoding="utf-8")
    if fragment is None:
        assert load_events(path) == __import__("json").loads(body)
    else:
        with pytest.raises(IngestError, match=fragment):
            load_events(path)
