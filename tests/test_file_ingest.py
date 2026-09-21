import json

import pytest

from cloudshield.telemetry.file_ingest import IngestError, load_events


def _write(tmp_path, name, content, binary=False):
    path = tmp_path / name
    if binary:
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def test_json_single_object_is_one_event(tmp_path):
    path = _write(tmp_path, "e.json", '{"a": 1}')

    assert load_events(path) == [{"a": 1}]


def test_json_array_yields_events_in_file_order(tmp_path):
    path = _write(tmp_path, "e.json", '[{"n": 3}, {"n": 1}, {"n": 2}]')

    assert [e["n"] for e in load_events(path)] == [3, 1, 2]


def test_jsonl_events_in_file_order_skipping_blank_lines(tmp_path):
    path = _write(tmp_path, "e.jsonl", '{"n": 1}\n\n   \n{"n": 2}\n')

    assert load_events(path) == [{"n": 1}, {"n": 2}]
    assert load_events(_write(tmp_path, "e.ndjson", '{"n": 1}\n')) == [{"n": 1}]


def test_malformed_jsonl_reports_physical_line_number(tmp_path):
    path = _write(tmp_path, "e.jsonl", '{"n": 1}\n\n{"n": \n{"n": 3}\n')

    with pytest.raises(IngestError, match=r"line 3"):
        load_events(path)


@pytest.mark.parametrize("name,content,fragment", [
    ("s.json", "42", "object or an array"),
    ("s.json", '"text"', "object or an array"),
    ("s.json", "null", "object or an array"),
    ("a.json", '[{"ok": 1}, 5]', "element 1"),
    ("l.jsonl", '{"ok": 1}\n[1, 2]\n', "line 2"),
    ("l.jsonl", '{"ok": 1}\n"scalar"\n', "line 2"),
])
def test_scalars_and_non_objects_are_rejected(tmp_path, name, content, fragment):
    with pytest.raises(IngestError, match=fragment):
        load_events(_write(tmp_path, name, content))


def test_max_events_cap_raises_instead_of_truncating(tmp_path):
    jsonl = _write(tmp_path, "e.jsonl", "".join('{"n": %d}\n' % i for i in range(5)))
    array = _write(tmp_path, "e.json", json.dumps([{"n": i} for i in range(5)]))

    assert len(load_events(jsonl, max_events=5)) == 5
    for path in (jsonl, array):
        with pytest.raises(IngestError, match="more than 4 events"):
            load_events(path, max_events=4)


@pytest.mark.parametrize("bad", [0, -1, True, "5", None])
def test_max_events_must_be_a_positive_integer(tmp_path, bad):
    with pytest.raises(ValueError, match="max_events"):
        load_events(_write(tmp_path, "e.json", "[]"), max_events=bad)


def test_empty_files_yield_no_events(tmp_path):
    assert load_events(_write(tmp_path, "e.json", "")) == []
    assert load_events(_write(tmp_path, "e.json", " \n ")) == []
    assert load_events(_write(tmp_path, "e.json", "[]")) == []
    assert load_events(_write(tmp_path, "e.jsonl", "")) == []
    assert load_events(_write(tmp_path, "e.jsonl", "\n\n")) == []


def test_loading_does_not_modify_the_file_and_results_are_independent(tmp_path):
    path = _write(tmp_path, "e.jsonl", '{"a": {"b": [1]}}\n')
    before = path.read_bytes()

    first = load_events(path)
    first[0]["a"]["b"].append(2)
    second = load_events(path)

    assert path.read_bytes() == before
    assert second == [{"a": {"b": [1]}}]


def test_utf8_including_bom_is_accepted_and_invalid_utf8_rejected(tmp_path):
    good = _write(tmp_path, "g.jsonl", b'\xef\xbb\xbf{"name": "caf\xc3\xa9"}\n', binary=True)
    bad = _write(tmp_path, "b.jsonl", b'{"name": "\xff\xfe"}\n', binary=True)

    assert load_events(good) == [{"name": "café"}]
    with pytest.raises(IngestError, match="UTF-8"):
        load_events(bad)


def test_nan_and_infinity_constants_are_rejected(tmp_path):
    with pytest.raises(IngestError, match="NaN"):
        load_events(_write(tmp_path, "e.json", '{"x": NaN}'))


def test_unsupported_extension_and_size_limit(tmp_path):
    with pytest.raises(IngestError, match="unsupported file type"):
        load_events(_write(tmp_path, "e.csv", "a,b"))
    with pytest.raises(IngestError, match="byte limit"):
        load_events(_write(tmp_path, "e.json", '{"a": "' + "x" * 100 + '"}'), max_bytes=50)


def test_missing_file_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_events(tmp_path / "missing.jsonl")
