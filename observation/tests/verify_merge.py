#!/usr/bin/env python3
"""
Verifies observation/database/merged.db against the two source
databases it was built from. Checks four things merge_observation_dbs.py's
own sanity block does NOT check:

  A. Row-count parity  -- every table's row count in merged.db equals
     benign_count + attack_count. Catches silent drops (e.g. a
     dedup_key collision swallowed by a constraint).
  B. Per-run count fields -- observation_runs.correlated_events_count
     and .ssh_sessions_count (recorded at capture time) match the
     ACTUAL row counts in merged.db for that run, for every imported run.
  C. Content fidelity -- for a sample of correlated_events rows
     originally from attack_observations.db, raw_json/src_ip/dst_ip/
     timestamp in merged.db at (old_id + offset) are byte-identical to
     the original at old_id. Catches an off-by-one or wrong-offset bug
     that row-count checks alone would miss.
  D. Referential + uniqueness integrity -- no child row points at a
     nonexistent correlated_events.id; no duplicate (run_id, dedup_key)
     in tcp_flows_raw / dns_events_raw.

Usage:
    python3 observation/tests/verify_merge.py \
        --benign observation/database/observations.db \
        --attack observation/database/attack_observations.db \
        --merged observation/database/merged.db
"""
from __future__ import annotations

import argparse
import random
import sqlite3
import sys

TABLES_ROW_PARITY = [
    "observation_runs",
    "attack_run_metadata",
    "correlated_events",
    "ssh_sessions",
    "tcp_flows_raw",
    "dns_events_raw",
    "process_observations",
    "dns_observations",
    "tls_observations",
    "tcp_flow_observations",
    "http_observations",
    "file_activity_events",
    "privilege_activity_events",
]

CHILD_TABLES = [
    "process_observations", "dns_observations", "tls_observations",
    "tcp_flow_observations", "http_observations",
    "file_activity_events", "privilege_activity_events",
]


def count(conn, schema, table):
    return conn.execute(f"SELECT COUNT(*) FROM {schema}.{table}").fetchone()[0]


def get_max(conn, schema, table, column):
    row = conn.execute(f"SELECT MAX({column}) FROM {schema}.{table}").fetchone()
    return row[0] or 0


def report(label, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {label}" + (f" -- {detail}" if detail else ""))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", required=True)
    ap.add_argument("--attack", required=True)
    ap.add_argument("--merged", required=True)
    ap.add_argument("--sample", type=int, default=25,
                     help="number of correlated_events rows to spot-check for content fidelity")
    args = ap.parse_args()

    conn = sqlite3.connect(args.merged)
    conn.execute("ATTACH DATABASE ? AS benign", (args.benign,))
    conn.execute("ATTACH DATABASE ? AS attack", (args.attack,))

    all_ok = True

    # ---- A. row-count parity -------------------------------------------
    print("\n== A. row-count parity ==")
    for table in TABLES_ROW_PARITY:
        b = count(conn, "benign", table)
        a = count(conn, "attack", table)
        m = count(conn, "main", table)
        ok = (b + a == m)
        all_ok &= report(
            f"{table}: benign={b} + attack={a} == merged={m}",
            ok, "" if ok else f"expected {b+a}, got {m}"
        )

    # ---- offsets (recomputed the same way merge_observation_dbs.py did) --
    run_id_offset = get_max(conn, "benign", "observation_runs", "run_id")
    event_id_offset = get_max(conn, "benign", "correlated_events", "id")

    # ---- B. per-run count fields ----------------------------------------
    print("\n== B. per-run recorded counts vs actual rows in merged.db ==")
    attack_runs = conn.execute("SELECT run_id, correlated_events_count, ssh_sessions_count "
                                "FROM attack.observation_runs").fetchall()
    mismatches = 0
    for old_run_id, rec_events, rec_ssh in attack_runs:
        new_run_id = old_run_id + run_id_offset
        actual_events = conn.execute(
            "SELECT COUNT(*) FROM correlated_events WHERE run_id = ?", (new_run_id,)
        ).fetchone()[0]
        actual_ssh = conn.execute(
            "SELECT COUNT(*) FROM ssh_sessions WHERE run_id = ?", (new_run_id,)
        ).fetchone()[0]
        if rec_events is not None and rec_events != actual_events:
            print(f"[FAIL] run {old_run_id}->{new_run_id}: recorded correlated_events_count="
                  f"{rec_events}, actual={actual_events}")
            mismatches += 1
        if rec_ssh is not None and rec_ssh != actual_ssh:
            print(f"[FAIL] run {old_run_id}->{new_run_id}: recorded ssh_sessions_count="
                  f"{rec_ssh}, actual={actual_ssh}")
            mismatches += 1
    ok = mismatches == 0
    all_ok &= report(f"{len(attack_runs)} imported runs checked", ok,
                      "" if ok else f"{mismatches} field mismatches")

    # ---- C. content fidelity spot-check ----------------------------------
    print(f"\n== C. content fidelity ({args.sample} sampled correlated_events rows) ==")
    attack_ids = [r[0] for r in conn.execute("SELECT id FROM attack.correlated_events")]
    sample_ids = random.sample(attack_ids, min(args.sample, len(attack_ids)))
    content_mismatches = 0
    for old_id in sample_ids:
        orig = conn.execute(
            "SELECT run_id, timestamp, src_ip, dst_ip, src_port, dst_port, "
            "process_pid, process_name, raw_json FROM attack.correlated_events WHERE id = ?",
            (old_id,),
        ).fetchone()
        new_id = old_id + event_id_offset
        copy = conn.execute(
            "SELECT run_id, timestamp, src_ip, dst_ip, src_port, dst_port, "
            "process_pid, process_name, raw_json FROM correlated_events WHERE id = ?",
            (new_id,),
        ).fetchone()
        if copy is None:
            print(f"[FAIL] old id {old_id} -> expected new id {new_id} not found in merged.db")
            content_mismatches += 1
            continue
        orig_run_id, *orig_rest = orig
        copy_run_id, *copy_rest = copy
        if copy_run_id != orig_run_id + run_id_offset:
            print(f"[FAIL] id {old_id}: run_id not offset correctly "
                  f"(orig={orig_run_id}, copy={copy_run_id}, expected={orig_run_id + run_id_offset})")
            content_mismatches += 1
        elif orig_rest != copy_rest:
            print(f"[FAIL] id {old_id} -> {new_id}: non-key columns differ")
            content_mismatches += 1
    ok = content_mismatches == 0
    all_ok &= report(f"{len(sample_ids)} rows compared", ok,
                      "" if ok else f"{content_mismatches} mismatches")

    # ---- D. referential + uniqueness integrity ----------------------------
    print("\n== D. referential + uniqueness integrity ==")
    for table in CHILD_TABLES:
        orphans = conn.execute(f"""
            SELECT COUNT(*) FROM {table} t
            LEFT JOIN correlated_events ce ON ce.id = t.correlated_event_id
            WHERE ce.id IS NULL
        """).fetchone()[0]
        all_ok &= report(f"{table}: no orphaned correlated_event_id", orphans == 0,
                          "" if orphans == 0 else f"{orphans} orphans")

    for table in ("tcp_flows_raw", "dns_events_raw"):
        dupes = conn.execute(f"""
            SELECT COUNT(*) FROM (
                SELECT run_id, dedup_key FROM {table}
                GROUP BY run_id, dedup_key HAVING COUNT(*) > 1
            )
        """).fetchone()[0]
        all_ok &= report(f"{table}: no duplicate (run_id, dedup_key)", dupes == 0,
                          "" if dupes == 0 else f"{dupes} duplicate keys")

    # foreign_key_check against the live schema, belt and braces
    fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    all_ok &= report("PRAGMA foreign_key_check", len(fk_violations) == 0,
                      "" if not fk_violations else f"{len(fk_violations)} violations: {fk_violations[:5]}")

    conn.execute("DETACH DATABASE benign")
    conn.execute("DETACH DATABASE attack")
    conn.close()

    print("\n" + ("ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED"))
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()