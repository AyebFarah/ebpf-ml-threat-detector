from __future__ import annotations
from sqlalchemy.orm import Session
from sqlalchemy import func, select
from observation.database.models import CorrelatedEventModel, ObservationRun, TlsObservation


def build_ja4_baseline(conn: Session, exclude_run_ids: list[int] | None = None) -> dict[str, int]:
    exclude_run_ids = exclude_run_ids or []
    statement = select(TlsObservation.ja4, func.count().label("count")).join(
        CorrelatedEventModel,
        CorrelatedEventModel.id == TlsObservation.correlated_event_id,
    ).join(
        ObservationRun, ObservationRun.run_id == CorrelatedEventModel.run_id,
    ).where(
        ObservationRun.label == "benign", ObservationRun.status == "completed",
        TlsObservation.ja4.is_not(None),
    ).group_by(TlsObservation.ja4)
    if exclude_run_ids:
        statement = statement.where(ObservationRun.run_id.not_in(exclude_run_ids))
    return {ja4: count for ja4, count in conn.execute(statement)}
