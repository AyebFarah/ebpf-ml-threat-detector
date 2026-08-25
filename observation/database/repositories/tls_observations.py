from __future__ import annotations
import json
import sqlite3


class TlsObservationsRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert(self, correlated_event_id: int, tls_block: dict) -> None:
        if not tls_block:
            return
        self.conn.execute(
            """
            INSERT INTO tls_observations (
                correlated_event_id, timestamp, sni, ja4, tls_version, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                correlated_event_id,
                tls_block.get("timestamp"),
                tls_block.get("sni"),
                tls_block.get("ja4"),
                tls_block.get("tls_version"),
                json.dumps(tls_block),
            ),
        )

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM tls_observations WHERE correlated_event_id = ?",
            (correlated_event_id,),
        ).fetchall()

    def for_ja4(self, ja4: str, run_id: int = None) -> list:
        if run_id is None:
            return self.conn.execute(
                "SELECT * FROM tls_observations WHERE ja4 = ?", (ja4,)
            ).fetchall()
        return self.conn.execute(
            "SELECT t.* FROM tls_observations t "
            "JOIN correlated_events ce ON ce.id = t.correlated_event_id "
            "WHERE t.ja4 = ? AND ce.run_id = ?",
            (ja4, run_id),
        ).fetchall()