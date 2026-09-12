#Full documentation on docs/011-feature-engineering-v1.md, section 'process_tree_depth_max
from __future__ import annotations
from sqlalchemy.orm import Session
from sqlalchemy import select
from observation.database.models import CorrelatedEventModel, ProcessObservation


def build_ancestry_map(conn: Session, run_id: int) -> dict[str, str | None]:
    """exec_id -> parent_exec_id, for every distinct process_observations row
    attached to a correlated_event in this run. Only covers processes that
    generated at least one network connection in this run"""
    rows = conn.execute(select(
        ProcessObservation.exec_id, ProcessObservation.parent_exec_id
    ).join(
        CorrelatedEventModel,
        CorrelatedEventModel.id == ProcessObservation.correlated_event_id,
    ).where(
        CorrelatedEventModel.run_id == run_id,
        ProcessObservation.exec_id.is_not(None),
    ).distinct())
    return {row.exec_id: row.parent_exec_id for row in rows}


class ProcessTreeDepthCalculator:
    """Walks exec_id -> parent_exec_id in memory. Caches per exec_id within
    a run so repeated windows sharing the same processes don't re-walk."""

    def __init__(self, ancestry: dict[str, str | None]):
        self._ancestry = ancestry
        self._cache: dict[str, int] = {}

    def depth(self, exec_id: str | None) -> int:
        if exec_id is None:
            return 0
        if exec_id in self._cache:
            return self._cache[exec_id]

        seen = set()
        depth = 0
        current = exec_id
        # Stop at: no parent recorded, parent not in this run's map
        # (truncated ancestry/parent predates the capture window), or a
        # cycle (shouldn't happen with real data, but don't hang on bad data).
        while current is not None and current in self._ancestry and current not in seen:
            seen.add(current)
            parent = self._ancestry[current]
            if parent is None:
                break
            depth += 1
            current = parent

        self._cache[exec_id] = depth
        return depth

    def max_depth(self, exec_ids: list[str]) -> int | None:
        depths = [self.depth(e) for e in exec_ids if e]
        return max(depths) if depths else None
