from __future__ import annotations
from sqlalchemy.orm import Session
from sqlalchemy import select

from observation.database.records import SshSessionRecord
from observation.database.models import SshSession

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
    def __init__(self, conn: Session):
        self.conn = conn

    def insert_many(self, run_id: int, records: list) -> int:
        sessions = [SshSessionRecord.from_record(run_id, r) for r in records]
        self.conn.add_all([
            SshSession(**{column: getattr(record, column) for column in _COLUMNS})
            for record in sessions
        ])
        return len(sessions)

    def for_run(self, run_id: int) -> list:
        return list(self.conn.execute(
            select(SshSession.__table__).where(
                SshSession.run_id == run_id
            ).order_by(SshSession.earliest_event_ts)
        ).mappings())
