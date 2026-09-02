from __future__ import annotations
import sqlite3
from collections import defaultdict


def build_ja4_baseline(conn: sqlite3.Connection) -> dict[str, int]:
    """Counts of each JA4 fingerprint across every benign-labeled run.
    Must be built BEFORE computing rare_ja4_ratio for any window —
    run this once per cli invocation covering the full corpus, not
    per-run, or 'rare' loses meaning."""
    rows = conn.execute(
        """
        SELECT tls.ja4 AS ja4
        FROM tls_observations tls
                 JOIN correlated_events ce ON ce.id = tls.correlated_event_id
                 JOIN observation_runs r ON r.run_id = ce.run_id
        WHERE r.label = 'benign' AND tls.ja4 IS NOT NULL
        """
    ).fetchall()
    counts = defaultdict(int)
    for r in rows:
        counts[r["ja4"]] += 1
    return dict(counts)