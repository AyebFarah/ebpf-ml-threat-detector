from __future__ import annotations
import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone

from observation.features.config import WINDOW_SECONDS, STRIDE_SECONDS, FEATURE_VERSION, AGGREGATION_VERSION
from observation.features import groups
from observation.features.process_tree import build_ancestry_map, ProcessTreeDepthCalculator


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def parse_label(raw_label: str | None) -> tuple[int, str | None, str | None]:
    if not raw_label or raw_label == "benign":
        return 0, None, None
    parts = raw_label.split(":")
    if parts[0] != "attack":
        return 0, None, None
    return 1, (parts[1] if len(parts) > 1 else None), (parts[2] if len(parts) > 2 else None)


def five_tuple_hash(src_ip, src_port, dst_ip, dst_port, transport) -> str:
    raw = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{transport}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def fetch_run_rows(conn: sqlite3.Connection, run_id: int) -> list[dict]:
    query = """
            SELECT
                ce.id AS event_id, ce.timestamp AS timestamp,
        ce.src_ip AS src_ip, ce.src_port AS src_port,
        ce.dst_ip AS dst_ip, ce.dst_port AS dst_port,
        ce.process_pid AS pid, ce.process_name AS binary,
        ce.tls_matched AS tls_matched, ce.dns_matched AS dns_matched,
        ce.http_matched AS http_matched, ce.tcp_flow_matched AS tcp_flow_matched,
        po.exec_id AS exec_id, po.parent_binary AS parent_binary, po.uid AS uid,
        dns.query_name AS dns_domain, dns.resolved_ip AS dns_resolved_ip,
        dns.rcode AS dns_rcode, dns.response_latency_ms AS dns_latency_ms,
        tls.sni AS tls_sni, tls.ja4 AS tls_ja4, tls.tls_version AS tls_version,
        flow.duration_seconds AS flow_duration,
        flow.bytes_out AS bytes_sent, flow.bytes_in AS bytes_received,
        flow.packets_out AS packets_sent, flow.packets_in AS packets_received,
        flow.termination_reason AS termination_reason,
        http.host AS http_host, http.method AS http_method,
        http.status_code AS http_status, http.path_length AS http_path_length,
        http.content_length AS http_content_length
            FROM correlated_events ce
                LEFT JOIN process_observations   po   ON po.correlated_event_id   = ce.id
                LEFT JOIN dns_observations       dns  ON dns.correlated_event_id  = ce.id
                LEFT JOIN tls_observations       tls  ON tls.correlated_event_id  = ce.id
                LEFT JOIN tcp_flow_observations  flow ON flow.correlated_event_id = ce.id
                LEFT JOIN http_observations      http ON http.correlated_event_id = ce.id
            WHERE ce.run_id = ?
            ORDER BY ce.timestamp \
            """
    rows = [dict(r) for r in conn.execute(query, (run_id,)).fetchall()]
    for r in rows:
        r["_ts"] = _parse_ts(r["timestamp"])
    return rows


def fetch_activity(conn: sqlite3.Connection, event_ids: list[int], table: str) -> dict:
    if not event_ids:
        return {}
    placeholders = ",".join("?" for _ in event_ids)
    cols = "correlated_event_id, timestamp, path, operations" if table == "file_activity_events" \
        else "correlated_event_id, timestamp, event_type, detail"
    rows = [dict(r) for r in conn.execute(
        f"SELECT {cols} FROM {table} WHERE correlated_event_id IN ({placeholders})", event_ids
    ).fetchall()]
    out = defaultdict(list)
    for r in rows:
        r["_ts"] = _parse_ts(r["timestamp"]) if r["timestamp"] else None
        out[r["correlated_event_id"]].append(r)
    return out


def fetch_ssh_sessions(conn: sqlite3.Connection, run_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM ssh_sessions WHERE run_id = ?", (run_id,)
    ).fetchall()]


def generate_windows(min_ts, max_ts, window_seconds, stride_seconds):
    windows = []
    start = min_ts
    while start <= max_ts:
        end = datetime.fromtimestamp(start.timestamp() + window_seconds, tz=timezone.utc)
        windows.append((start, end))
        start = datetime.fromtimestamp(start.timestamp() + stride_seconds, tz=timezone.utc)
    return windows


def _aggregate(rows, window_start, window_end, file_activity, privilege_activity,
               ssh_in_window, ja4_baseline, depth_calc) -> dict:
    event_ids = [r["event_id"] for r in rows]
    file_events, privilege_events = [], []
    for eid in event_ids:
        file_events.extend(file_activity.get(eid, []))
        privilege_events.extend(privilege_activity.get(eid, []))

    traffic = groups.traffic_volume(rows)

    result = {}
    result.update(groups.basic_counts(rows, len(ssh_in_window)))
    result.update(groups.network_topology(rows))
    result.update(traffic)
    result.update(groups.flow_dynamics(rows))
    result.update(groups.rate_and_burstiness(rows, window_start, window_end, traffic))
    result.update(groups.dns_features(rows))
    result.update(groups.tls_features(rows, ja4_baseline))
    result.update(groups.http_features(rows))
    result.update(groups.process_features(rows, depth_calc))
    result.update(groups.privilege_and_file_features(rows, file_events, privilege_events, window_end))
    result.update(groups.ssh_features(ssh_in_window))
    result["contributing_event_ids"] = json.dumps(event_ids)
    return result


def build_feature_windows(conn: sqlite3.Connection, run_id: int, ja4_baseline: dict,
                          window_seconds: int = WINDOW_SECONDS,
                          stride_seconds: int = STRIDE_SECONDS) -> list[dict]:
    run_row = conn.execute(
        "SELECT scenario, label FROM observation_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    if run_row is None:
        return []
    scenario = run_row["scenario"]
    label_int, attack_family, attack_technique = parse_label(run_row["label"])

    rows = fetch_run_rows(conn, run_id)
    if not rows:
        return []

    event_ids = [r["event_id"] for r in rows]
    file_activity = fetch_activity(conn, event_ids, "file_activity_events")
    privilege_activity = fetch_activity(conn, event_ids, "privilege_activity_events")
    ssh_sessions = fetch_ssh_sessions(conn, run_id)

    ancestry = build_ancestry_map(conn, run_id)
    depth_calc = ProcessTreeDepthCalculator(ancestry)

    timestamps = [r["_ts"] for r in rows]
    windows = generate_windows(min(timestamps), max(timestamps), window_seconds, stride_seconds)

    results = []
    for w_start, w_end in windows:
        in_window = [r for r in rows if w_start <= r["_ts"] < w_end]
        if not in_window:
            continue

        ssh_in_window = [
            s for s in ssh_sessions
            if s["earliest_event_ts"] and w_start <= _parse_ts(s["earliest_event_ts"]) < w_end
        ]

        results.append(_build_row(
            run_id, w_start, w_end, "host", str(run_id), in_window,
            file_activity, privilege_activity, ssh_in_window, ja4_baseline, depth_calc,
            scenario, label_int, attack_family, attack_technique,
        ))

        by_exec = defaultdict(list)
        for r in in_window:
            if r["exec_id"]:
                by_exec[r["exec_id"]].append(r)
        for exec_id, exec_rows in by_exec.items():
            results.append(_build_row(
                run_id, w_start, w_end, "process", exec_id, exec_rows,
                file_activity, privilege_activity, [], ja4_baseline, depth_calc,
                scenario, label_int, attack_family, attack_technique,
            ))

        by_flow = defaultdict(list)
        for r in in_window:
            key = five_tuple_hash(r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"], "tcp")
            by_flow[key].append(r)
        for flow_id, flow_rows in by_flow.items():
            results.append(_build_row(
                run_id, w_start, w_end, "flow", flow_id, flow_rows,
                file_activity, privilege_activity, [], ja4_baseline, depth_calc,
                scenario, label_int, attack_family, attack_technique,
            ))

    return results


def _build_row(run_id, w_start, w_end, entity_type, entity_id, rows,
               file_activity, privilege_activity, ssh_in_window, ja4_baseline, depth_calc,
               scenario, label_int, attack_family, attack_technique) -> dict:
    features = _aggregate(rows, w_start, w_end, file_activity, privilege_activity,
                          ssh_in_window, ja4_baseline, depth_calc)
    return {
        "run_id": run_id,
        "window_start_ts": w_start.isoformat(),
        "window_end_ts": w_end.isoformat(),
        "entity_type": entity_type,
        "entity_id": entity_id,
        "label": label_int,
        "scenario": scenario,
        "attack_family": attack_family,
        "attack_technique": attack_technique,
        "feature_version": FEATURE_VERSION,
        "aggregation_version": AGGREGATION_VERSION,
        **features,
    }