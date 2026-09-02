#Full documentation on docs/011-feature-engineering-v1.md, section 'process_tree_depth_max
from __future__ import annotations
import sqlite3


def build_ancestry_map(conn: sqlite3.Connection, run_id: int) -> dict[str, str | None]:
    """exec_id -> parent_exec_id, for every distinct process_observations row
    attached to a correlated_event in this run. Only covers processes that
    generated at least one network connection in this run"""
    rows = conn.execute(
        """
        SELECT DISTINCT po.exec_id, po.parent_exec_id
        FROM process_observations po
                 JOIN correlated_events ce ON ce.id = po.correlated_event_id
        WHERE ce.run_id = ? AND po.exec_id IS NOT NULL
        """,
        (run_id,),
    ).fetchall()
    return {r["exec_id"]: r["parent_exec_id"] for r in rows}


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