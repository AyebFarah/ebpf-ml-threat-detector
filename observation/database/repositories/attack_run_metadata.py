from __future__ import annotations
import json
from typing import Optional

from sqlalchemy import select

from sqlalchemy.orm import Session
from observation.database.models import AttackRunMetadata, ObservationRun


class AttackRunMetadataRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert(self, run_id: int, attack_family: str, attack_technique: str,
               scenario: str, tool: Optional[str] = None, tool_version: Optional[str] = None,
               target_host: Optional[str] = None, target_port: Optional[int] = None,
               intensity: Optional[str] = None, parameters: Optional[dict] = None,
               attack_start_ts: Optional[str] = None, attack_end_ts: Optional[str] = None,
               expected_behavior: Optional[str] = None, notes: Optional[str] = None,
               operator: Optional[str] = None, manifest_path: Optional[str] = None) -> None:
        self.conn.add(AttackRunMetadata(
            run_id=run_id, attack_family=attack_family,
            attack_technique=attack_technique, scenario=scenario, tool=tool,
            tool_version=tool_version, target_host=target_host,
            target_port=target_port, intensity=intensity,
            parameters=json.dumps(parameters) if parameters else None,
            attack_start_ts=attack_start_ts, attack_end_ts=attack_end_ts,
            expected_behavior=expected_behavior, notes=notes, operator=operator,
            manifest_path=manifest_path,
        ))

    def get(self, run_id: int):
        return self.conn.execute(select(AttackRunMetadata.__table__).where(
            AttackRunMetadata.run_id == run_id
        )).mappings().first()


def validate_attack_runs_have_metadata(conn: Session) -> list[int]:
    """Returns run_ids where label LIKE 'attack:%' but no attack_run_metadata
    row exists"""
    rows = conn.execute(
        select(ObservationRun.run_id).outerjoin(
            AttackRunMetadata, AttackRunMetadata.run_id == ObservationRun.run_id
        ).where(
            ObservationRun.label.like("attack:%"),
            AttackRunMetadata.run_id.is_(None),
        )
    ).scalars()
    return list(rows)
