import math

import pytest

from cloudshield.replay import (
    compute_delay,
    parse_event_timestamp,
    replay,
)


class Sleeper:
    def __init__(self):
        self.calls = []

    def __call__(self, seconds):
        self.calls.append(seconds)


def _events(*timestamps):
    return [{"n": i, "timestamp": ts} for i, ts in enumerate(timestamps)]


def _ts(seconds):
    return f"2024-08-05T10:{seconds // 60:02d}:{seconds % 60:02d}Z"


def _run(events, mode="instant", speed=1.0, sleeper=None, **kwargs):
    sleeper = sleeper if sleeper is not None else Sleeper()
    out = list(replay(events, lambda e: e.get("timestamp"), mode, speed, sleep=sleeper, **kwargs))
    return out, sleeper.calls


def test_instant_mode_never_sleeps():
    out, sleeps = _run(_events(_ts(0), _ts(30), "2030-01-01T00:00:00Z"))

    assert len(out) == 3 and sleeps == []


def test_accelerated_delay_is_gap_divided_by_speed():
    _, sleeps = _run(_events(_ts(0), _ts(20)), mode="accelerated", speed=10)

    assert sleeps == [2.0]


def test_accelerated_uses_each_gap_and_skips_zero_gaps():
    _, sleeps = _run(_events(_ts(0), _ts(10), _ts(10), _ts(40)), mode="accelerated", speed=2,
                     max_sleep_seconds=100)

    assert sleeps == [5.0, 15.0]


def test_realtime_uses_original_gap_and_ignores_speed():
    _, sleeps = _run(_events(_ts(0), _ts(7)), mode="realtime", speed=100)

    assert sleeps == [7.0]


def test_compute_delay_examples():
    assert compute_delay(20, "accelerated", 10) == 2.0
    assert compute_delay(20, "realtime", 10, max_sleep_seconds=100) == 20.0
    assert compute_delay(20, "realtime", 10) == 10.0  # default cap
    assert compute_delay(20, "instant", 10) == 0.0
    assert compute_delay(-5, "realtime", 1) == 0.0
    assert compute_delay(0, "accelerated", 4) == 0.0


@pytest.mark.parametrize("speed", [0, -1, -0.5, math.nan, math.inf, True, "2", None])
def test_speed_must_be_positive_and_finite(speed):
    with pytest.raises(ValueError, match="speed"):
        list(replay([], lambda e: None, "accelerated", speed))
    with pytest.raises(ValueError, match="speed"):
        compute_delay(1, "accelerated", speed)


def test_unknown_mode_and_bad_max_sleep_are_rejected():
    with pytest.raises(ValueError, match="mode"):
        list(replay([], lambda e: None, "warp", 1))
    for bad in (-1, math.nan, math.inf):
        with pytest.raises(ValueError, match="max_sleep_seconds"):
            list(replay([], lambda e: None, "realtime", 1, max_sleep_seconds=bad))


@pytest.mark.parametrize("bad", [None, "", "   ", "not-a-time", 12345, "2024-08-05T10:00:00", "2024-13-45T99:00:00Z"])
def test_missing_or_invalid_timestamps_never_sleep_or_crash(bad):
    events = _events(_ts(0), bad, _ts(20))
    out, sleeps = _run(events, mode="accelerated", speed=10)

    assert [e["n"] for e in out] == [0, 1, 2]
    assert sleeps == [2.0]  # only the 0 -> 20s gap between the two valid timestamps


def test_first_event_never_sleeps_even_with_late_timestamp():
    _, sleeps = _run(_events("2024-08-05T23:59:59Z"), mode="realtime")

    assert sleeps == []


def test_backwards_timestamp_neither_sleeps_nor_moves_the_clock_back():
    events = _events(_ts(30), _ts(10), _ts(40))
    out, sleeps = _run(events, mode="realtime")

    assert [e["n"] for e in out] == [0, 1, 2]  # never reordered
    assert sleeps == [10.0]  # 30s -> 40s measured from the latest valid timestamp


def test_sleep_is_capped_for_huge_gaps():
    events = _events("2024-08-05T10:00:00Z", "2124-08-05T10:00:00Z")
    _, sleeps = _run(events, mode="realtime")

    assert sleeps == [10.0]
    _, capped = _run(events, mode="accelerated", speed=1, max_sleep_seconds=0.5)
    assert capped == [0.5]
    _, none = _run(events, mode="realtime", max_sleep_seconds=0)
    assert none == []


def test_event_order_and_identity_are_preserved():
    events = _events(_ts(5), None, _ts(1), _ts(50), "junk")
    out, _ = _run(events, mode="instant")

    assert out == events
    assert all(a is b for a, b in zip(out, events))


def test_replay_is_lazy_and_yields_before_sleeping_for_the_next():
    sleeper = Sleeper()
    iterator = replay(_events(_ts(0), _ts(10)), lambda e: e["timestamp"], "realtime", sleep=sleeper)

    next(iterator)
    assert sleeper.calls == []
    next(iterator)
    assert sleeper.calls == [10.0]


def test_parse_event_timestamp_handles_z_offsets_and_nanoseconds():
    assert parse_event_timestamp("2024-08-05T10:00:00Z") is not None
    assert parse_event_timestamp("2024-08-05T10:00:00.123456Z") is not None
    assert parse_event_timestamp("2024-08-05T12:00:00+02:00") == parse_event_timestamp("2024-08-05T10:00:00Z")
    assert parse_event_timestamp("2024-08-05T21:56:56.097601933Z") is not None  # nanosecond precision (official sample)
