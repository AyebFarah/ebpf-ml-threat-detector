from __future__ import annotations
from sqlalchemy.orm import Session
from sqlalchemy import select
from observation.database.models import PrivilegeActivityEvent


class PrivilegeActivityRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert_many(self, correlated_event_id: int, privilege_activity: list) -> None:
        if not privilege_activity:
            return
        self.conn.add_all([PrivilegeActivityEvent(
            correlated_event_id=correlated_event_id, timestamp=item.get("timestamp"),
            event_type=item.get("event_type"),
            detail=str(item.get("detail")) if item.get("detail") is not None else None,
            source_event_key=item.get("source_event_key"),
        ) for item in privilege_activity])

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return list(self.conn.execute(select(PrivilegeActivityEvent.__table__).where(
            PrivilegeActivityEvent.correlated_event_id == correlated_event_id
        ).order_by(PrivilegeActivityEvent.timestamp)).mappings())
