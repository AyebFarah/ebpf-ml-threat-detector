from __future__ import annotations
import sqlite3
from collections import defaultdict


def build_ja4_baseline(conn: sqlite3.Connection, exclude_run_ids: list[int] | None = None) -> dict[str, int]:
    exclude_run_ids = exclude_run_ids or []
    exclude_clause = ""
    params = []
    if exclude_run_ids:
        placeholders = ",".join("?" for _ in exclude_run_ids)
        exclude_clause = f"AND r.run_id NOT IN ({placeholders})"
        params = list(exclude_run_ids)

    rows = conn.execute(
        f"""
        SELECT tls.ja4 AS ja4
        FROM tls_observations tls
        JOIN correlated_events ce ON ce.id = tls.correlated_event_id
        JOIN observation_runs r ON r.run_id = ce.run_id
        WHERE r.label = 'benign' AND r.status = 'completed'
              AND tls.ja4 IS NOT NULL {exclude_clause}
        """,
        params,
    ).fetchall()
    counts = defaultdict(int)
    for r in rows:
        counts[r["ja4"]] += 1
    return dict(counts)