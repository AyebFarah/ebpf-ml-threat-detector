from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update

from sqlalchemy.orm import Session
from observation.database.models import ObservationRun


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunsRepository:
    def __init__(self, conn: Session):
        self.conn = conn

    def start_run(self, scenario: str, label: str = "benign",
                  notes: Optional[str] = None, started_at: Optional[str] = None) -> int:
        started_at = started_at or _now()
        model = ObservationRun(
            started_at=started_at, status="running", scenario=scenario,
            label=label, notes=notes,
        )
        self.conn.add(model)
        self.conn.flush()
        return model.run_id

    def complete_run(self, run_id: int, correlated_events_count: int,
                     ssh_sessions_count: int, source_correlated_file: Optional[str] = None,
                     source_ssh_sessions_file: Optional[str] = None,
                     duration_ms: Optional[int] = None,
                     status: str = "completed",
                     ended_at: Optional[str] = None,
                     ) -> None:
        ended_at = ended_at or _now()
        self.conn.execute(update(ObservationRun).where(
            ObservationRun.run_id == run_id
        ).values(
            ended_at=ended_at, status=status,
            correlated_events_count=correlated_events_count,
            ssh_sessions_count=ssh_sessions_count,
            source_correlated_file=source_correlated_file,
            source_ssh_sessions_file=source_ssh_sessions_file,
            duration_ms=duration_ms,
        ))

    def mark_completed(self, run_id: int) -> None:
        """Flip a run from awaiting_metadata to completed. Called by the
        attack wrapper only after attack_run_metadata has been
        successfully inserted in its own transaction."""
        self.conn.execute(update(ObservationRun).where(
            ObservationRun.run_id == run_id
        ).values(status="completed"))

    def fail_run(self, run_id: int, error: str) -> None:
        self.conn.execute(update(ObservationRun).where(
            ObservationRun.run_id == run_id
        ).values(ended_at=_now(), status=f"failed: {error}"[:500]))

    def get_run(self, run_id: int):
        return self.conn.execute(
            select(ObservationRun.__table__).where(ObservationRun.run_id == run_id)
        ).mappings().first()

    def latest_run(self):
        return self.conn.execute(
            select(ObservationRun.__table__).order_by(ObservationRun.run_id.desc()).limit(1)
        ).mappings().first()
