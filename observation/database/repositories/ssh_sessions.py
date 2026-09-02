from __future__ import annotations
import sqlite3
from ..models import SshSessionRecord

_COLUMNS = (
    "run_id", "session_key", "username", "src_ip", "src_port", "pid",
    "earliest_event_ts", "auth_success_ts", "auth_method",
    "session_opened_ts", "session_closed_ts", "session_duration_seconds",
    "disconnected_ts", "tcp_connect_matched", "tcp_connect_dst_ip",
    "tcp_connect_time_delta_ms", "tcp_close_matched", "tcp_close_timestamp",
    "connection_duration_seconds", "execve_matched", "execve_binary",
    "execve_timestamp", "raw_json",
)


class SshSessionsRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert_many(self, run_id: int, records: list) -> int:
        sessions = [SshSessionRecord.from_record(run_id, r) for r in records]
        placeholders = ", ".join("?" for _ in _COLUMNS)
        self.conn.executemany(
            f"INSERT INTO ssh_sessions ({', '.join(_COLUMNS)}) VALUES ({placeholders})",
            [tuple(getattr(s, col) for col in _COLUMNS) for s in sessions],
        )
        return len(sessions)

    def for_run(self, run_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM ssh_sessions WHERE run_id = ? ORDER BY earliest_event_ts", (run_id,)
        ).fetchall()