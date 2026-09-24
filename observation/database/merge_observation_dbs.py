#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from sqlalchemy import MetaData, Table, create_engine, func, insert, select, text
from sqlalchemy.engine import Connection

from observation.database.models import (
    Base,
    ObservationRun,
    AttackRunMetadata,
    CorrelatedEventModel,
    SshSession,
    TcpFlowRaw,
    DnsEventRaw,
    ProcessObservation,
    DnsObservation,
    TlsObservation,
    TcpFlowObservation,
    HttpObservation,
    FileActivityEvent,
    PrivilegeActivityEvent,
    FeatureWindow,
)

ATTACH_SCHEMA = "atk"

# Tables whose `id` PK and (if present) `run_id` FK must be offset.
RUN_SCOPED = [
    ObservationRun.__table__,
    AttackRunMetadata.__table__,
    CorrelatedEventModel.__table__,
    SshSession.__table__,
    TcpFlowRaw.__table__,
    DnsEventRaw.__table__,
]

# Children of correlated_events: own `id` + `correlated_event_id` offset.
CHILDREN_OF_EVENTS = [
    ProcessObservation.__table__,
    DnsObservation.__table__,
    TlsObservation.__table__,
    TcpFlowObservation.__table__,
    HttpObservation.__table__,
    FileActivityEvent.__table__,
    PrivilegeActivityEvent.__table__,
]


def _attached_table(conn: Connection, base: Table, md: MetaData) -> Table:
    """Reflect the same table from the attached 'atk' schema."""
    return Table(base.name, md, schema=ATTACH_SCHEMA, autoload_with=conn)


def _max(conn: Connection, table: Table, column: str) -> int:
    return conn.execute(
        select(func.coalesce(func.max(table.c[column]), 0))
    ).scalar_one()


def _offset_select(table: Table, atk: Table, offsets: dict[str, int]):
    """
    Build `SELECT <col> [+ offset] AS <col>, ... FROM atk.<table>`.
    `offsets` maps column name -> integer offset (only for columns
    that need shifting).
    """
    cols = []
    for col in table.columns:
        if col.name in offsets:
            cols.append((atk.c[col.name] + offsets[col.name]).label(col.name))
        else:
            cols.append(atk.c[col.name].label(col.name))
    return select(*cols)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--benign", required=True)
    ap.add_argument("--attack", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    benign_path = Path(args.benign)
    attack_path = Path(args.attack)
    out_path = Path(args.output)

    if not benign_path.exists():
        sys.exit(f"[merge] not found: {benign_path}")
    if not attack_path.exists():
        sys.exit(f"[merge] not found: {attack_path}")
    if out_path.exists():
        sys.exit(f"[merge] refusing to overwrite existing {out_path}")

    print(f"[merge] copying {benign_path} -> {out_path}")
    shutil.copy2(benign_path, out_path)

    engine = create_engine(f"sqlite:///{out_path.as_posix()}")

    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys = OFF"))
        conn.exec_driver_sql(f"ATTACH DATABASE '{attack_path.as_posix()}' AS {ATTACH_SCHEMA}")

        # --- sanity: attack DB must be migrated ------------------------
        has_metadata = conn.execute(text(
            f"SELECT 1 FROM {ATTACH_SCHEMA}.sqlite_master "
            "WHERE type='table' AND name='attack_run_metadata'"
        )).first()
        if not has_metadata:
            sys.exit("[merge] attack_observations.db is missing attack_run_metadata "
                     "-- wrong file, or migrations were never applied to it.")

        # --- reflect attack-side tables --------------------------------
        atk_md = MetaData()
        atk_tables: dict[str, Table] = {}
        for base in RUN_SCOPED + CHILDREN_OF_EVENTS:
            atk_tables[base.name] = _attached_table(conn, base, atk_md)

        atk_runs = atk_tables[ObservationRun.__tablename__]
        atk_run_ids = [r[0] for r in conn.execute(select(atk_runs.c.run_id))]
        if not atk_run_ids:
            sys.exit("[merge] atk.observation_runs is empty, nothing to merge")

        # --- compute offsets -------------------------------------------
        run_id_offset      = _max(conn, ObservationRun.__table__, "run_id")
        event_id_offset    = _max(conn, CorrelatedEventModel.__table__, "id")
        ssh_id_offset      = _max(conn, SshSession.__table__, "id")
        tcpflow_id_offset  = _max(conn, TcpFlowRaw.__table__, "id")
        dns_id_offset      = _max(conn, DnsEventRaw.__table__, "id")

        print(f"[merge] run_id offset:               +{run_id_offset}")
        print(f"[merge] correlated_events.id offset: +{event_id_offset}")
        print(f"[merge] ssh_sessions.id offset:      +{ssh_id_offset}")
        print(f"[merge] tcp_flows_raw.id offset:     +{tcpflow_id_offset}")
        print(f"[merge] dns_events_raw.id offset:    +{dns_id_offset}")
        print(f"[merge] importing {len(atk_run_ids)} runs "
              f"({min(atk_run_ids)}..{max(atk_run_ids)} -> "
              f"{min(atk_run_ids)+run_id_offset}..{max(atk_run_ids)+run_id_offset})")

        # --- 1. observation_runs ---------------------------------------
        tbl = ObservationRun.__table__
        atk = atk_tables[tbl.name]
        conn.execute(insert(tbl).from_select(
            [c.name for c in tbl.columns],
            _offset_select(tbl, atk, {"run_id": run_id_offset}),
        ))

        # --- 2. attack_run_metadata (PK is run_id) ---------------------
        tbl = AttackRunMetadata.__table__
        atk = atk_tables[tbl.name]
        conn.execute(insert(tbl).from_select(
            [c.name for c in tbl.columns],
            _offset_select(tbl, atk, {"run_id": run_id_offset}),
        ))

        # --- 3. correlated_events (id + run_id) ------------------------
        tbl = CorrelatedEventModel.__table__
        atk = atk_tables[tbl.name]
        conn.execute(insert(tbl).from_select(
            [c.name for c in tbl.columns],
            _offset_select(tbl, atk, {"id": event_id_offset, "run_id": run_id_offset}),
        ))

        # --- 4. children of correlated_events --------------------------
        for tbl in CHILDREN_OF_EVENTS:
            atk = atk_tables[tbl.name]
            own_offset = _max(conn, tbl, "id")
            conn.execute(insert(tbl).from_select(
                [c.name for c in tbl.columns],
                _offset_select(tbl, atk, {
                    "id": own_offset,
                    "correlated_event_id": event_id_offset,
                }),
            ))
            print(f"[merge] {tbl.name}: own id offset +{own_offset}")

        # --- 5. ssh_sessions (id + run_id) -----------------------------
        tbl = SshSession.__table__
        atk = atk_tables[tbl.name]
        conn.execute(insert(tbl).from_select(
            [c.name for c in tbl.columns],
            _offset_select(tbl, atk, {"id": ssh_id_offset, "run_id": run_id_offset}),
        ))

        # --- 6. tcp_flows_raw (id + run_id) ----------------------------
        tbl = TcpFlowRaw.__table__
        atk = atk_tables[tbl.name]
        conn.execute(insert(tbl).from_select(
            [c.name for c in tbl.columns],
            _offset_select(tbl, atk, {"id": tcpflow_id_offset, "run_id": run_id_offset}),
        ))

        # --- 7. dns_events_raw (id + run_id) ---------------------------
        tbl = DnsEventRaw.__table__
        atk = atk_tables[tbl.name]
        conn.execute(insert(tbl).from_select(
            [c.name for c in tbl.columns],
            _offset_select(tbl, atk, {"id": dns_id_offset, "run_id": run_id_offset}),
        ))

        # --- 8. feature_windows: intentionally NOT imported ------------
        fw = atk_tables.get("feature_windows") or _attached_table(
            conn, FeatureWindow.__table__, atk_md
        )
        fw_count = conn.execute(select(func.count()).select_from(fw)).scalar_one()
        if fw_count:
            print(f"[merge] WARNING: atk.feature_windows had {fw_count} rows -- "
                  f"NOT imported (contributing_event_ids would be stale). "
                  f"Re-run `python -m observation.features.cli --all` on the "
                  f"merged db for every run, including these.")

        # --- sanity checks ---------------------------------------------
        print("\n[merge] sanity checks")
        runs = ObservationRun.__table__
        events = CorrelatedEventModel.__table__
        meta = AttackRunMetadata.__table__

        total_runs = conn.execute(select(func.count()).select_from(runs)).scalar_one()

        dup_runs = conn.execute(
            select(runs.c.run_id, func.count().label("c"))
            .group_by(runs.c.run_id)
            .having(func.count() > 1)
        ).all()

        orphan_events = conn.execute(
            select(func.count())
            .select_from(events.outerjoin(runs, runs.c.run_id == events.c.run_id))
            .where(runs.c.run_id.is_(None))
        ).scalar_one()

        unlabeled = conn.execute(
            select(func.count())
            .select_from(
                runs.outerjoin(meta, meta.c.run_id == runs.c.run_id)
            )
            .where(
                runs.c.label.like("attack:%"),
                meta.c.run_id.is_(None),
                runs.c.status.in_(["completed", "awaiting_metadata"]),
            )
        ).scalar_one()

        print(f"[merge] total observation_runs:                 {total_runs}")
        print(f"[merge] duplicate run_ids:                      {len(dup_runs)}")
        print(f"[merge] correlated_events with no matching run: {orphan_events}")
        print(f"[merge] attack-labeled runs missing metadata:   {unlabeled}")

        if dup_runs or orphan_events or unlabeled:
            print("[merge] ^ one or more checks failed, investigate before windowing")
        else:
            print("[merge] all checks passed")

    print(f"\n[merge] done -> {out_path}")


if __name__ == "__main__":
    main()
