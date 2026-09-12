from __future__ import annotations
from sqlalchemy.orm import Session
from sqlalchemy import select
from observation.database.models import CorrelatedEventModel, FileActivityEvent


class FileActivityRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def insert_many(self, correlated_event_id: int, file_activity: list) -> None:
        if not file_activity:
            return
        self.conn.add_all([FileActivityEvent(
            correlated_event_id=correlated_event_id, timestamp=item.get("timestamp"),
            path=item.get("path"), operations=",".join(item.get("operations") or []),
            source_event_key=item.get("source_event_key"),
        ) for item in file_activity])

    def for_correlated_event(self, correlated_event_id: int) -> list:
        return list(self.conn.execute(select(FileActivityEvent.__table__).where(
            FileActivityEvent.correlated_event_id == correlated_event_id
        ).order_by(FileActivityEvent.timestamp)).mappings())

    def for_path(self, path: str, run_id: int = None) -> list:
        statement = select(FileActivityEvent.__table__).join(
            CorrelatedEventModel,
            CorrelatedEventModel.id == FileActivityEvent.correlated_event_id,
        ).where(FileActivityEvent.path == path)
        if run_id is not None:
            statement = statement.where(CorrelatedEventModel.run_id == run_id)
        return list(self.conn.execute(
            statement.order_by(FileActivityEvent.timestamp)
        ).mappings())
