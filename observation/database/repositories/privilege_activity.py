from __future__ import annotations
import sqlite3


class PrivilegeActivityRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert_many(self, correlated_event_id: int, privilege_activity: list) -> None:
        if not privilege_activity:
            return
        self.conn.executemany(
            "INSERT INTO privilege_activity_events (correlated_event_id, timestamp, event_type, detail) "
            "VALUES (?, ?, ?, ?)",
            [
                (correlated_event_id, p.get("timestamp"), p.get("event_type"),
                 str(p.get("detail")) if p.get("detail") is not None else None)
                for p in privilege_activity
            ],
        )

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM privilege_activity_events WHERE correlated_event_id = ? ORDER BY timestamp",
            (correlated_event_id,),
        ).fetchall()