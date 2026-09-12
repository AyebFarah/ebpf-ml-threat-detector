from __future__ import annotations
import json
from sqlalchemy.orm import Session
from sqlalchemy import select
from observation.database.models import CorrelatedEventModel, HttpObservation


class HttpObservationsRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert(self, correlated_event_id: int, http_block: dict) -> None:
        if not http_block:
            return
        self.conn.add(HttpObservation(
            correlated_event_id=correlated_event_id,
            request_timestamp=http_block.get("request_timestamp"),
            response_timestamp=http_block.get("response_timestamp"),
            method=http_block.get("method"), host=http_block.get("host"),
            path_hash=http_block.get("path_hash"), path_length=http_block.get("path_length"),
            user_agent_hash=http_block.get("user_agent_hash"),
            status_code=http_block.get("status_code"), content_type=http_block.get("content_type"),
            content_length=http_block.get("content_length"), raw_json=json.dumps(http_block),
        ))

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return list(self.conn.execute(select(HttpObservation.__table__).where(
            HttpObservation.correlated_event_id == correlated_event_id
        )).mappings())

    def for_host(self, host: str, run_id: int = None) -> list:
        if run_id is None:
            statement = select(HttpObservation.__table__).where(HttpObservation.host == host)
        else:
            statement = select(HttpObservation.__table__).join(
                CorrelatedEventModel, CorrelatedEventModel.id == HttpObservation.correlated_event_id
            ).where(HttpObservation.host == host, CorrelatedEventModel.run_id == run_id)
        return list(self.conn.execute(statement).mappings())
