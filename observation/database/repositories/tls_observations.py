from __future__ import annotations
import json
from sqlalchemy.orm import Session
from sqlalchemy import select
from observation.database.models import CorrelatedEventModel, TlsObservation


class TlsObservationsRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert(self, correlated_event_id: int, tls_block: dict) -> None:
        if not tls_block:
            return
        self.conn.add(TlsObservation(
            correlated_event_id=correlated_event_id, timestamp=tls_block.get("timestamp"),
            sni=tls_block.get("sni"), ja4=tls_block.get("ja4"),
            tls_version=tls_block.get("tls_version"), raw_json=json.dumps(tls_block),
        ))

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return list(self.conn.execute(select(TlsObservation.__table__).where(
            TlsObservation.correlated_event_id == correlated_event_id
        )).mappings())

    def for_ja4(self, ja4: str, run_id: int = None) -> list:
        if run_id is None:
            statement = select(TlsObservation.__table__).where(TlsObservation.ja4 == ja4)
        else:
            statement = select(TlsObservation.__table__).join(
                CorrelatedEventModel, CorrelatedEventModel.id == TlsObservation.correlated_event_id
            ).where(TlsObservation.ja4 == ja4, CorrelatedEventModel.run_id == run_id)
        return list(self.conn.execute(statement).mappings())
