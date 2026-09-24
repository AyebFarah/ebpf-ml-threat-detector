"""
Converts feature_windows timestamps into simulated real-time delays, so
runner.py can feed a recorded run through the pipeline "as if live"
rather than as fast as the CPU allows, useful for demoing detection
latency meaningfully instead of just batch-scoring everything at once.
"""
from __future__ import annotations
from datetime import datetime


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def compute_delays(window_start_timestamps: list[str], speed: float = 1.0) -> list[float]:
    """Returns the number of seconds to sleep before emitting each
    window, relative to the previous one, scaled by `speed` (2.0 = twice
    as fast as real time, 0 = no delay / as-fast-as-possible)."""
    if not window_start_timestamps:
        return []
    times = [parse_ts(t) for t in window_start_timestamps]
    delays = [0.0]
    for i in range(1, len(times)):
        gap = (times[i] - times[i - 1]).total_seconds()
        delays.append(max(0.0, gap / speed) if speed else 0.0)
    return delays
