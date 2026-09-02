from __future__ import annotations
import json
import sqlite3
from typing import Optional


class AttackRunMetadataRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert(self, run_id: int, attack_family: str, attack_technique: str,
               scenario: str, tool: Optional[str] = None, tool_version: Optional[str] = None,
               target_host: Optional[str] = None, target_port: Optional[int] = None,
               intensity: Optional[str] = None, parameters: Optional[dict] = None,
               attack_start_ts: Optional[str] = None, attack_end_ts: Optional[str] = None,
               expected_behavior: Optional[str] = None, notes: Optional[str] = None,
               operator: Optional[str] = None, manifest_path: Optional[str] = None) -> None:
        self.conn.execute(
            """
            INSERT INTO attack_run_metadata (
                run_id, attack_family, attack_technique, scenario, tool, tool_version,
                target_host, target_port, intensity, parameters,
                attack_start_ts, attack_end_ts, expected_behavior, notes, operator, manifest_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, attack_family, attack_technique, scenario, tool, tool_version,
             target_host, target_port, intensity, json.dumps(parameters) if parameters else None,
             attack_start_ts, attack_end_ts, expected_behavior, notes, operator, manifest_path),
        )

    def get(self, run_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM attack_run_metadata WHERE run_id = ?", (run_id,)
        ).fetchone()


def validate_attack_runs_have_metadata(conn: sqlite3.Connection) -> list[int]:
    """Returns run_ids where label LIKE 'attack:%' but no attack_run_metadata
    row exists"""
    rows = conn.execute(
        """
        SELECT r.run_id FROM observation_runs r
                                 LEFT JOIN attack_run_metadata m ON m.run_id = r.run_id
        WHERE r.label LIKE 'attack:%' AND m.run_id IS NULL
        """
    ).fetchall()
    return [r["run_id"] for r in rows]