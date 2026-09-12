from __future__ import annotations
import json
from sqlalchemy.orm import Session
from sqlalchemy import select

from observation.database.models import CorrelatedEventModel, ProcessObservation


class ProcessObservationsRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert(self, correlated_event_id: int, process_context_block: dict) -> None:
        if not process_context_block:
            return
        self.conn.add(ProcessObservation(
            correlated_event_id=correlated_event_id,
            timestamp=process_context_block.get("start_time"),
            exec_id=process_context_block.get("exec_id"),
            parent_exec_id=process_context_block.get("parent_exec_id"),
            parent_binary=process_context_block.get("parent_binary"),
            arguments=process_context_block.get("arguments"),
            uid=process_context_block.get("uid"), cwd=process_context_block.get("cwd"),
            raw_json=json.dumps(process_context_block),
        ))

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return list(self.conn.execute(select(ProcessObservation.__table__).where(
            ProcessObservation.correlated_event_id == correlated_event_id
        )).mappings())

    def for_exec_id(self, exec_id: str, run_id: int = None) -> list:
        if run_id is None:
            statement = select(ProcessObservation.__table__).where(
                ProcessObservation.exec_id == exec_id
            )
        else:
            statement = select(ProcessObservation.__table__).join(
                CorrelatedEventModel,
                CorrelatedEventModel.id == ProcessObservation.correlated_event_id,
            ).where(ProcessObservation.exec_id == exec_id, CorrelatedEventModel.run_id == run_id)
        return list(self.conn.execute(statement).mappings())
