from __future__ import annotations
import sqlite3
from ..models import CorrelatedEvent
from .process_observations import ProcessObservationsRepository
from .dns_observations import DnsObservationsRepository
from .tls_observations import TlsObservationsRepository
from .tcp_flow_observations import TcpFlowObservationsRepository
from .http_observations import HttpObservationsRepository
from .file_activity import FileActivityRepository
from .privilege_activity import PrivilegeActivityRepository

_CORE_COLUMNS = (
    "run_id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "transport", "direction", "process_pid", "process_name",
    "dns_matched", "dns_method", "dns_time_delta_ms", "dns_response_latency_ms",
    "tls_matched", "tls_method", "tls_time_delta_ms",
    "ssh_matched", "ssh_method", "ssh_time_delta_ms",
    "tcp_flow_matched", "tcp_flow_method", "tcp_flow_time_delta_ms",
    "http_matched", "http_method", "http_time_delta_ms",
    "process_context_matched", "process_context_method",
    "file_activity_count", "file_activity_method",
    "privilege_activity_count", "privilege_activity_method",
    "raw_json",
)


class CorrelatedEventsRepository:
    """
    Persists the RESULT of correlation already computed in Python by
    correlator.py -- it does not perform any matching itself. Inserts
    the core correlated_events row, then delegates to each specialized
    child repository using the parent's newly-generated id.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.process_repo = ProcessObservationsRepository(conn)
        self.dns_repo = DnsObservationsRepository(conn)
        self.tls_repo = TlsObservationsRepository(conn)
        self.tcp_flow_repo = TcpFlowObservationsRepository(conn)
        self.http_repo = HttpObservationsRepository(conn)
        self.file_repo = FileActivityRepository(conn)
        self.privilege_repo = PrivilegeActivityRepository(conn)

    def insert_many(self, run_id: int, records: list) -> int:
        events = [CorrelatedEvent.from_record(run_id, r) for r in records]
        placeholders = ", ".join("?" for _ in _CORE_COLUMNS)
        insert_sql = f"INSERT INTO correlated_events ({', '.join(_CORE_COLUMNS)}) VALUES ({placeholders})"

        for e in events:
            cur = self.conn.execute(insert_sql, tuple(getattr(e, col) for col in _CORE_COLUMNS))
            correlated_event_id = cur.lastrowid

            self.process_repo.insert(correlated_event_id, e.process_context_block)
            self.dns_repo.insert(correlated_event_id, e.dns_block)
            self.tls_repo.insert(correlated_event_id, e.tls_block)
            self.tcp_flow_repo.insert(correlated_event_id, e.tcp_block)
            self.http_repo.insert(correlated_event_id, e.http_block)
            self.file_repo.insert_many(correlated_event_id, e.file_activity)
            self.privilege_repo.insert_many(correlated_event_id, e.privilege_activity)

        return len(events)

    def for_run(self, run_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM correlated_events WHERE run_id = ? ORDER BY timestamp", (run_id,)
        ).fetchall()