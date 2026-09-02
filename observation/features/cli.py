"""
Usage:
    python -m observation.features.cli --run-id <run_id>
    python -m observation.features.cli --all
    python -m observation.features.cli --exclude <run_id>
    """

import argparse
from ..database.connection import connect, apply_migrations
from . import extractor, baseline
from .repositories.feature_windows import FeatureWindowsRepository


def _resolve_run_ids(conn, run_ids: list[int] | None, all_runs: bool, exclude: list[int]) -> list[int]:
    if all_runs:
        rows = conn.execute(
            "SELECT run_id FROM observation_runs WHERE status = 'completed'"
        ).fetchall()
        return [r["run_id"] for r in rows if r["run_id"] not in exclude]
    return [rid for rid in (run_ids or []) if rid not in exclude]


def _process_run(run_id: int, ja4_baseline: dict):
    """Own connect() per run: one commit/rollback boundary per run_id,
    so one bad run doesn't roll back or block others in a --all batch."""
    with connect() as conn:
        windows = extractor.build_feature_windows(conn, run_id, ja4_baseline)
        by_entity = {}
        for w in windows:
            by_entity[w["entity_type"]] = by_entity.get(w["entity_type"], 0) + 1
        repo = FeatureWindowsRepository(conn)
        repo.upsert_for_run(run_id, windows)
        print(f"[features] run_id={run_id}: {len(windows)} windows {by_entity}")


def main():
    parser = argparse.ArgumentParser(description="Build feature_windows from correlated_events")
    parser.add_argument("--run-id", type=int, action="append", dest="run_ids",
                        help="Process one run_id (repeatable: --run-id 7 --run-id 8)")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--exclude", type=int, nargs="*", default=[])
    args = parser.parse_args()

    apply_migrations()

    with connect() as conn:
        print("[features] building JA4 rarity baseline from benign runs...")
        ja4_baseline = baseline.build_ja4_baseline(conn)
        print(f"[features] baseline: {len(ja4_baseline)} distinct JA4 fingerprints")
        run_ids = _resolve_run_ids(conn, args.run_ids, args.all, args.exclude)

    if not run_ids:
        parser.error("Specify --run-id N (repeatable) or --all")

    failures = []
    for run_id in run_ids:
        try:
            _process_run(run_id, ja4_baseline)
        except Exception as exc:
            print(f"[features] FAILED run_id={run_id}: {exc}")
            failures.append(run_id)

    if failures:
        print(f"[features] completed with {len(failures)} failure(s): {failures}")
    else:
        print(f"[features] all {len(run_ids)} run(s) processed successfully")


if __name__ == "__main__":
    main()