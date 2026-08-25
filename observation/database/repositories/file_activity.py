from __future__ import annotations
import sqlite3


class FileActivityRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert_many(self, correlated_event_id: int, file_activity: list) -> None:
        if not file_activity:
            return
        self.conn.executemany(
            "INSERT INTO file_activity_events (correlated_event_id, timestamp, path, operations) "
            "VALUES (?, ?, ?, ?)",
            [
                (correlated_event_id, f.get("timestamp"), f.get("path"),
                 ",".join(f.get("operations") or []))
                for f in file_activity
            ],
        )

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM file_activity_events WHERE correlated_event_id = ? ORDER BY timestamp",
            (correlated_event_id,),
        ).fetchall()

    def for_path(self, path: str, run_id: int = None) -> list:
        if run_id is None:
            return self.conn.execute(
                "SELECT fae.*, ce.run_id FROM file_activity_events fae "
                "JOIN correlated_events ce ON ce.id = fae.correlated_event_id "
                "WHERE fae.path = ? ORDER BY fae.timestamp",
                (path,),
            ).fetchall()
        return self.conn.execute(
            "SELECT fae.* FROM file_activity_events fae "
            "JOIN correlated_events ce ON ce.id = fae.correlated_event_id "
            "WHERE fae.path = ? AND ce.run_id = ? ORDER BY fae.timestamp",
            (path, run_id),
        ).fetchall()