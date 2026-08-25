from __future__ import annotations
import sqlite3
from datetime import datetime, timezone
from typing import Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunsRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def start_run(self) -> int:
        cur = self.conn.execute(
            "INSERT INTO observation_runs (started_at, status) VALUES (?, ?)",
            (_now(), "running"),
        )
        return cur.lastrowid

    def complete_run(self, run_id: int, correlated_events_count: int,
                     ssh_sessions_count: int, source_correlated_file: Optional[str] = None,
                     source_ssh_sessions_file: Optional[str] = None) -> None:
        self.conn.execute(
            """
            UPDATE observation_runs
            SET ended_at = ?, status = ?, correlated_events_count = ?,
                ssh_sessions_count = ?, source_correlated_file = ?,
                source_ssh_sessions_file = ?
            WHERE run_id = ?
            """,
            (_now(), "completed", correlated_events_count, ssh_sessions_count,
             source_correlated_file, source_ssh_sessions_file, run_id),
        )

    def fail_run(self, run_id: int, error: str) -> None:
        self.conn.execute(
            "UPDATE observation_runs SET ended_at = ?, status = ? WHERE run_id = ?",
            (_now(), f"failed: {error}"[:500], run_id),
        )

    def get_run(self, run_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM observation_runs WHERE run_id = ?", (run_id,)
        ).fetchone()

    def latest_run(self) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM observation_runs ORDER BY run_id DESC LIMIT 1"
        ).fetchone()