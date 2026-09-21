"""Replay events in order, optionally paced by their original timestamps.

Modes:
- ``instant``: never sleeps (tests, evaluation, CI, benchmarks).
- ``accelerated``: sleeps (timestamp gap / speed) between events.
- ``realtime``: sleeps the original timestamp gap (speed is ignored).

Safety: speed must be a positive finite number; a missing, unparsable,
timezone-less or backwards timestamp never produces a sleep; every sleep is
capped at ``max_sleep_seconds``, so bad data cannot stall a replay.
"""
import math
import time
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, Optional, TypeVar

T = TypeVar("T")

MODE_INSTANT = "instant"
MODE_ACCELERATED = "accelerated"
MODE_REALTIME = "realtime"
MODES = (MODE_INSTANT, MODE_ACCELERATED, MODE_REALTIME)
DEFAULT_MAX_SLEEP_SECONDS = 10.0


def parse_event_timestamp(value: object) -> Optional[datetime]:
    """Parse an RFC 3339 timestamp; None if absent, malformed or timezone-less."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def validate_replay_settings(mode: str, speed: float, max_sleep_seconds: float) -> None:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {list(MODES)}, got {mode!r}")
    if isinstance(speed, bool) or not isinstance(speed, (int, float)) or not math.isfinite(speed) or speed <= 0:
        raise ValueError(f"speed must be a positive finite number, got {speed!r}")
    if (isinstance(max_sleep_seconds, bool) or not isinstance(max_sleep_seconds, (int, float))
            or not math.isfinite(max_sleep_seconds) or max_sleep_seconds < 0):
        raise ValueError(f"max_sleep_seconds must be a finite number >= 0, got {max_sleep_seconds!r}")


def compute_delay(gap_seconds: float, mode: str, speed: float,
                  max_sleep_seconds: float = DEFAULT_MAX_SLEEP_SECONDS) -> float:
    """Seconds to sleep for a timestamp gap: 0 for instant, gap/speed accelerated, gap realtime."""
    validate_replay_settings(mode, speed, max_sleep_seconds)
    if mode == MODE_INSTANT or gap_seconds <= 0:
        return 0.0
    effective_speed = 1.0 if mode == MODE_REALTIME else float(speed)
    return min(gap_seconds / effective_speed, float(max_sleep_seconds))


def replay(
    items: Iterable[T],
    timestamp_of: Callable[[T], object],
    mode: str = MODE_INSTANT,
    speed: float = 1.0,
    *,
    max_sleep_seconds: float = DEFAULT_MAX_SLEEP_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> Iterator[T]:
    """Yield items in their given order, sleeping between them per the mode.

    The gap is measured from the latest valid timestamp seen so far, so an
    out-of-order (backwards) or unparsable timestamp neither sleeps nor moves
    the clock backwards. Items are never reordered or dropped.
    """
    validate_replay_settings(mode, speed, max_sleep_seconds)
    clock: Optional[datetime] = None
    for item in items:
        current = parse_event_timestamp(timestamp_of(item))
        if current is not None:
            if clock is not None:
                delay = compute_delay((current - clock).total_seconds(), mode, speed, max_sleep_seconds)
                if delay > 0:
                    sleep(delay)
            if clock is None or current > clock:
                clock = current
        yield item
