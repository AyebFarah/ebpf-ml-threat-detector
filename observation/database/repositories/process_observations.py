from __future__ import annotations
import json
import sqlite3


class ProcessObservationsRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert(self, correlated_event_id: int, process_context_block: dict) -> None:
        if not process_context_block:
            return
        self.conn.execute(
            """
            INSERT INTO process_observations (
                correlated_event_id, timestamp, exec_id, parent_exec_id,
                parent_binary, arguments, uid, cwd, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                correlated_event_id,
                process_context_block.get("start_time"),
                process_context_block.get("exec_id"),
                process_context_block.get("parent_exec_id"),
                process_context_block.get("parent_binary"),
                process_context_block.get("arguments"),
                process_context_block.get("uid"),
                process_context_block.get("cwd"),
                json.dumps(process_context_block),
            ),
        )

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return self.conn.execute(
            "SELECT * FROM process_observations WHERE correlated_event_id = ?",
            (correlated_event_id,),
        ).fetchall()

    def for_exec_id(self, exec_id: str, run_id: int = None) -> list:
        if run_id is None:
            return self.conn.execute(
                "SELECT * FROM process_observations WHERE exec_id = ?", (exec_id,)
            ).fetchall()
        return self.conn.execute(
            "SELECT p.* FROM process_observations p "
            "JOIN correlated_events ce ON ce.id = p.correlated_event_id "
            "WHERE p.exec_id = ? AND ce.run_id = ?",
            (exec_id, run_id),
        ).fetchall()