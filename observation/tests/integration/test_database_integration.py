from __future__ import annotations

from sqlalchemy import event

from observation.database.models import CorrelatedEventModel, ObservationRun
from observation.database.repositories.correlated_events import CorrelatedEventsRepository
import pytest

def test_deleting_run_cascades_to_correlated_events(engine, session):
    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _record):
        dbapi_connection.execute("PRAGMA foreign_keys = ON")

    run = ObservationRun(started_at="2026-01-01T00:00:00Z", scenario="test", label="benign")
    session.add(run)
    session.flush()

    event_row = CorrelatedEventModel(
        run_id=run.run_id, timestamp="2026-01-01T00:00:01Z", raw_json="{}",
    )
    session.add(event_row)
    session.commit()

    session.delete(run)
    session.commit()

    assert session.query(CorrelatedEventModel).filter_by(run_id=run.run_id).count() == 0


def test_run_and_correlated_event_relationship(session):
    run = ObservationRun(started_at="2026-01-01T00:00:00Z", scenario="test", label="benign")
    event_row = CorrelatedEventModel(timestamp="2026-01-01T00:00:01Z", raw_json="{}")
    run.correlated_events.append(event_row)

    session.add(run)
    session.commit()

    assert event_row.run is run
    assert event_row in run.correlated_events


def test_insert_many_rolls_back_on_failure(session):
    run = ObservationRun(started_at="2026-01-01T00:00:00Z", scenario="test", label="benign")
    session.add(run)
    session.flush()

    broken_record = {"timestamp": None}  # missing required "timestamp" triggers a failure downstream

    with pytest.raises(Exception):
        CorrelatedEventsRepository(session).insert_many(run.run_id, [broken_record])
        session.flush()

    session.rollback()

    remaining = session.query(CorrelatedEventModel).filter_by(run_id=run.run_id).count()
    assert remaining == 0