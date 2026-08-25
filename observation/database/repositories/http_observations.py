from __future__ import annotations
import json
import sqlite3


class HttpObservationsRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert(self, correlated_event_id: int, http_block: dict) -> None:
        if not http_block:
            return
        self.conn.execute(
            """
            INSERT INTO http_observations (
                correlated_event_id, request_timestamp, response_timestamp,
                method, host, path_hash, path_length, user_agent_hash,
                status_code, content_type, content_length, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                correlated_event_id,
                http_block.get("request_timestamp"),
                http_block.get("response_timestamp"),
                http_block.get("method"),
                http_block.get("host"),
                http_block.get("path_hash"),
                http_block.get("path_length"),
                http_block.get("user_agent_hash"),
                http_block.get("status_code"),
                http_block.get("content_type"),
                http_block.get("content_length"),
                json.dumps(http_block),
            ),
        )

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM http_observations WHERE correlated_event_id = ?",
            (correlated_event_id,),
        ).fetchall()

    def for_host(self, host: str, run_id: int = None) -> list:
        if run_id is None:
            return self.conn.execute(
                "SELECT * FROM http_observations WHERE host = ?", (host,)
            ).fetchall()
        return self.conn.execute(
            "SELECT h.* FROM http_observations h "
            "JOIN correlated_events ce ON ce.id = h.correlated_event_id "
            "WHERE h.host = ? AND ce.run_id = ?",
            (host, run_id),
        ).fetchall()