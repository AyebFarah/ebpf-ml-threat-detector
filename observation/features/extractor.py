from __future__ import annotations
import hashlib
import json
from sqlalchemy.orm import Session
from sqlalchemy import select
from collections import defaultdict
from datetime import datetime, timezone

from .config import WINDOW_SECONDS, STRIDE_SECONDS, FEATURE_VERSION, AGGREGATION_VERSION
from . import groups
from .process_tree import build_ancestry_map, ProcessTreeDepthCalculator
from observation.database.models import (
    CorrelatedEventModel, DnsEventRaw, DnsObservation, FileActivityEvent,
    HttpObservation, ObservationRun, PrivilegeActivityEvent,
    ProcessObservation, SshSession, TcpFlowObservation, TcpFlowRaw,
    TlsObservation,
)

FLOW_ONLY_AGGREGATION_VERSION = "flow_only_15s_5s_v1"


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


def fetch_run_rows(conn: Session, run_id: int) -> list[dict]:
    statement = select(
        CorrelatedEventModel.id.label("event_id"), CorrelatedEventModel.timestamp,
        CorrelatedEventModel.src_ip, CorrelatedEventModel.src_port,
        CorrelatedEventModel.dst_ip, CorrelatedEventModel.dst_port,
        CorrelatedEventModel.process_pid.label("pid"), CorrelatedEventModel.process_name.label("binary"),
        CorrelatedEventModel.tls_matched, CorrelatedEventModel.dns_matched,
        CorrelatedEventModel.http_matched, CorrelatedEventModel.tcp_flow_matched,
        ProcessObservation.exec_id, ProcessObservation.parent_binary, ProcessObservation.uid,
        DnsObservation.query_name.label("dns_domain"), DnsObservation.resolved_ip.label("dns_resolved_ip"),
        DnsObservation.rcode.label("dns_rcode"), DnsObservation.response_latency_ms.label("dns_latency_ms"),
        TlsObservation.sni.label("tls_sni"), TlsObservation.ja4.label("tls_ja4"),
        TlsObservation.tls_version,
        TcpFlowObservation.duration_ms.label("flow_duration_ms"),
        TcpFlowObservation.bytes_out.label("bytes_sent"), TcpFlowObservation.bytes_in.label("bytes_received"),
        TcpFlowObservation.packets_out.label("packets_sent"), TcpFlowObservation.packets_in.label("packets_received"),
        TcpFlowObservation.termination_reason,
        HttpObservation.host.label("http_host"), HttpObservation.method.label("http_method"),
        HttpObservation.status_code.label("http_status"), HttpObservation.path_length.label("http_path_length"),
        HttpObservation.content_length.label("http_content_length"),
    ).outerjoin(ProcessObservation, ProcessObservation.correlated_event_id == CorrelatedEventModel.id
    ).outerjoin(DnsObservation, DnsObservation.correlated_event_id == CorrelatedEventModel.id
    ).outerjoin(TlsObservation, TlsObservation.correlated_event_id == CorrelatedEventModel.id
    ).outerjoin(TcpFlowObservation, TcpFlowObservation.correlated_event_id == CorrelatedEventModel.id
    ).outerjoin(HttpObservation, HttpObservation.correlated_event_id == CorrelatedEventModel.id
    ).where(CorrelatedEventModel.run_id == run_id).order_by(CorrelatedEventModel.timestamp)
    rows = [dict(row) for row in conn.execute(statement).mappings()]

    for r in rows:
        r["_ts"] = _parse_ts(r["timestamp"])

        # Database stores milliseconds.
        # Feature groups use seconds as floating-point values.
        r["flow_duration"] = (
            r["flow_duration_ms"] / 1000.0
            if r["flow_duration_ms"] is not None
            else None
        )

    return rows


def fetch_run_tcp_flows_raw(conn: Session, run_id: int) -> list[dict]:
    """Every TCP flow captured for this run, independent of correlator
    matching. Used two ways:
      1. Merged into host-level network_topology() alongside
         correlated_events rows, always, since correlated_events can
         under-represent real network activity (e.g. attacker-initiated
         scans, where Tetragon's tcp_connect never fires on this host).
      2. As the sole source for flow-only windowing when correlated_events
         is completely empty for the run.
    Returns pseudo-correlated-event-shaped rows so the existing
    aggregation pipeline (groups.*) can be reused unchanged in flow-only
    mode, and so timestamp-based window filtering works identically to
    correlated_events rows.
    """
    rows = conn.execute(select(
        TcpFlowRaw.id, TcpFlowRaw.src_ip, TcpFlowRaw.src_port, TcpFlowRaw.dst_ip,
        TcpFlowRaw.dst_port, TcpFlowRaw.start_ts, TcpFlowRaw.end_ts,
        TcpFlowRaw.duration_ms, TcpFlowRaw.termination_reason,
        TcpFlowRaw.packets_out, TcpFlowRaw.packets_in,
        TcpFlowRaw.bytes_out, TcpFlowRaw.bytes_in,
    ).where(TcpFlowRaw.run_id == run_id)).mappings()

    pseudo_rows = []
    for r in rows:
        r = dict(r)
        pseudo_rows.append({
            "event_id": f"flow_raw_{r['id']}",
            "timestamp": r["start_ts"],
            "_ts": _parse_ts(r["start_ts"]),
            "src_ip": r["src_ip"], "src_port": r["src_port"],
            "dst_ip": r["dst_ip"], "dst_port": r["dst_port"],
            "pid": None, "binary": None,
            "tls_matched": False, "dns_matched": False,
            "http_matched": False, "tcp_flow_matched": True,
            "exec_id": None, "parent_binary": None, "uid": None,
            "dns_domain": None, "dns_resolved_ip": None,
            "dns_rcode": None, "dns_latency_ms": None,
            "tls_sni": None, "tls_ja4": None, "tls_version": None,
            "flow_duration": (
                r["duration_ms"] / 1000.0
                if r["duration_ms"] is not None
                else None
            ),
            "bytes_sent": r["bytes_out"], "bytes_received": r["bytes_in"],
            "packets_sent": r["packets_out"], "packets_received": r["packets_in"],
            "termination_reason": r["termination_reason"],
            "http_host": None, "http_method": None,
            "http_status": None, "http_path_length": None,
            "http_content_length": None,
        })
    return pseudo_rows

def fetch_run_dns_events_raw(conn: Session, run_id: int) -> list[dict]:
    """Every DNS query/response captured for this run, independent of
    correlator matching. Merged into host-level dns_features() alongside
    correlated_events rows, always, since correlated_events can never
    see NXDOMAIN responses at all (they have no answer IP, so the
    correlator's resolved_ip-based matching, never attaches
    them to a connection). This is the DNS equivalent of the
    tcp_flows_raw gap: dns_tunneling-style traffic can be completely
    invisible to dns_features() without this merge, even when
    correlated_events isn't empty for the run.
    """
    rows = conn.execute(select(
        DnsEventRaw.id, DnsEventRaw.dedup_key, DnsEventRaw.timestamp,
        DnsEventRaw.query_name, DnsEventRaw.rcode, DnsEventRaw.resolved_ip,
        DnsEventRaw.ttl,
    ).where(DnsEventRaw.run_id == run_id)).mappings()

    pseudo_events = []
    for r in rows:
        r = dict(r)
        pseudo_events.append({
            "event_id": f"dns_raw_{r['id']}",
            "dedup_key": r["dedup_key"],
            "timestamp": r["timestamp"],
            "_ts": _parse_ts(r["timestamp"]) if r["timestamp"] else None,
            "dns_domain": r["query_name"],
            "dns_rcode": r["rcode"],
            "dns_resolved_ip": r["resolved_ip"],
            "dns_latency_ms": None,
        })
    return pseudo_events


def fetch_activity(conn: Session, event_ids: list[int], table: str) -> dict:
    if not event_ids:
        return {}
    model = FileActivityEvent if table == "file_activity_events" else PrivilegeActivityEvent
    rows = [dict(row) for row in conn.execute(select(model.__table__).where(
        model.correlated_event_id.in_(event_ids)
    )).mappings()]
    out = defaultdict(list)
    for r in rows:
        r["_ts"] = _parse_ts(r["timestamp"]) if r["timestamp"] else None
        out[r["correlated_event_id"]].append(r)
    return out


def fetch_ssh_sessions(conn: Session, run_id: int) -> list[dict]:
    return [dict(row) for row in conn.execute(select(SshSession.__table__).where(
        SshSession.run_id == run_id
    )).mappings()]


def generate_windows(min_ts, max_ts, window_seconds, stride_seconds):
    windows = []
    start = min_ts
    while start <= max_ts:
        end = datetime.fromtimestamp(start.timestamp() + window_seconds, tz=timezone.utc)
        windows.append((start, end))
        start = datetime.fromtimestamp(start.timestamp() + stride_seconds, tz=timezone.utc)
    return windows


def _aggregate(rows, window_start, window_end, file_activity, privilege_activity,
               ssh_in_window, ja4_baseline, depth_calc, extra_flows=None,
               extra_dns_events=None) -> dict:
    event_ids = [r["event_id"] for r in rows]
    file_events, privilege_events = [], []
    for eid in event_ids:
        file_events.extend(file_activity.get(eid, []))
        privilege_events.extend(privilege_activity.get(eid, []))

    traffic = groups.traffic_volume(rows)

    result = {}
    result.update(groups.basic_counts(rows, len(ssh_in_window), extra_flows=extra_flows))
    result.update(groups.network_topology(rows, extra_flows=extra_flows))
    result.update(traffic)
    result.update(groups.flow_dynamics(rows))
    result.update(groups.rate_and_burstiness(rows, window_start, window_end, traffic))
    result.update(groups.dns_features(rows, extra_events=extra_dns_events))
    result.update(groups.tls_features(rows, ja4_baseline))
    result.update(groups.http_features(rows))
    result.update(groups.process_features(rows, depth_calc))
    result.update(groups.privilege_and_file_features(rows, file_events, privilege_events, window_end))
    result.update(groups.ssh_features(ssh_in_window))
    result["contributing_event_ids"] = json.dumps(event_ids)
    return result


def build_feature_windows(conn: Session, run_id: int, ja4_baseline: dict,
                          window_seconds: int = WINDOW_SECONDS,
                          stride_seconds: int = STRIDE_SECONDS) -> list[dict]:
    """Correlated_events is enriched with tcp_flows_raw for host-level
    network topology, always (not only when correlated_events is empty),
    since correlated_events can under-represent real network activity
    even when it isn't completely empty (e.g. network_discovery producing
    2 correlated_events out of 63 real flows). See docs/011."""
    run_row = conn.execute(select(
        ObservationRun.scenario, ObservationRun.label
    ).where(ObservationRun.run_id == run_id)).mappings().first()
    if run_row is None:
        return []
    scenario = run_row["scenario"]
    label_int, attack_family, attack_technique = parse_label(run_row["label"])

    rows = fetch_run_rows(conn, run_id)
    flow_rows = fetch_run_tcp_flows_raw(conn, run_id)
    dns_rows = fetch_run_dns_events_raw(conn, run_id)

    if not rows and not flow_rows and not dns_rows:
        return []

    if rows:
        return _build_windows_from_rows(
            conn, run_id, rows, ja4_baseline, window_seconds, stride_seconds,
            scenario, label_int, attack_family, attack_technique,
            aggregation_version=AGGREGATION_VERSION,
            extra_flow_rows=flow_rows,
            extra_dns_rows=dns_rows,
        )

    print(f"[features] run_id={run_id}: no correlated_events rows, "
          f"building flow-only windows from {len(flow_rows)} tcp_flows_raw rows "
          f"and {len(dns_rows)} dns_events_raw rows")
    return _build_windows_from_rows(
        conn, run_id, flow_rows, ja4_baseline, window_seconds, stride_seconds,
        scenario, label_int, attack_family, attack_technique,
        aggregation_version=FLOW_ONLY_AGGREGATION_VERSION,
        flow_only=True,
        extra_dns_rows=dns_rows,
    )


def _build_windows_from_rows(conn, run_id, rows, ja4_baseline, window_seconds, stride_seconds,
                              scenario, label_int, attack_family, attack_technique,
                              aggregation_version, flow_only=False, extra_flow_rows=None,
                              extra_dns_rows=None) -> list[dict]:
    event_ids = [r["event_id"] for r in rows]

    if flow_only:
        file_activity, privilege_activity, ssh_sessions = {}, {}, []
        ancestry = {}
    else:
        file_activity = fetch_activity(conn, event_ids, "file_activity_events")
        privilege_activity = fetch_activity(conn, event_ids, "privilege_activity_events")
        ssh_sessions = fetch_ssh_sessions(conn, run_id)
        ancestry = build_ancestry_map(conn, run_id)

    depth_calc = ProcessTreeDepthCalculator(ancestry)

    timestamps = [r["_ts"] for r in rows]
    if extra_flow_rows:
        timestamps += [f["_ts"] for f in extra_flow_rows if f["_ts"]]
    if extra_dns_rows:
        timestamps += [d["_ts"] for d in extra_dns_rows if d["_ts"]]
    if not timestamps:
        return []
    windows = generate_windows(min(timestamps), max(timestamps), window_seconds, stride_seconds)

    results = []
    for w_start, w_end in windows:
        in_window = [r for r in rows if w_start <= r["_ts"] < w_end]

        in_window_extra_flows = None
        if extra_flow_rows:
            in_window_extra_flows = [f for f in extra_flow_rows if f["_ts"] and w_start <= f["_ts"] < w_end]

        in_window_extra_dns = None
        if extra_dns_rows:
            in_window_extra_dns = [d for d in extra_dns_rows if d["_ts"] and w_start <= d["_ts"] < w_end]

        if not in_window and not in_window_extra_flows and not in_window_extra_dns:
            continue

        ssh_in_window = [
            s for s in ssh_sessions
            if s["earliest_event_ts"] and w_start <= _parse_ts(s["earliest_event_ts"]) < w_end
        ]

        results.append(_build_row(
            run_id, w_start, w_end, "host", str(run_id), in_window,
            file_activity, privilege_activity, ssh_in_window, ja4_baseline, depth_calc,
            scenario, label_int, attack_family, attack_technique, aggregation_version,
            extra_flows=in_window_extra_flows, extra_dns_events=in_window_extra_dns,
        ))

        if not flow_only:
            by_exec = defaultdict(list)
            for r in in_window:
                if r["exec_id"]:
                    by_exec[r["exec_id"]].append(r)
            for exec_id, exec_rows in by_exec.items():
                results.append(_build_row(
                    run_id, w_start, w_end, "process", exec_id, exec_rows,
                    file_activity, privilege_activity, [], ja4_baseline, depth_calc,
                    scenario, label_int, attack_family, attack_technique, aggregation_version,
                ))

        by_flow = defaultdict(list)
        for r in in_window:
            key = five_tuple_hash(r["src_ip"], r["src_port"], r["dst_ip"], r["dst_port"], "tcp")
            by_flow[key].append(r)
        for flow_id, flow_rows_in_window in by_flow.items():
            results.append(_build_row(
                run_id, w_start, w_end, "flow", flow_id, flow_rows_in_window,
                file_activity, privilege_activity, [], ja4_baseline, depth_calc,
                scenario, label_int, attack_family, attack_technique, aggregation_version,
            ))

    return results


def _build_row(run_id, w_start, w_end, entity_type, entity_id, rows,
               file_activity, privilege_activity, ssh_in_window, ja4_baseline, depth_calc,
               scenario, label_int, attack_family, attack_technique, aggregation_version,
               extra_flows=None, extra_dns_events=None) -> dict:
    features = _aggregate(rows, w_start, w_end, file_activity, privilege_activity,
                          ssh_in_window, ja4_baseline, depth_calc,
                          extra_flows=extra_flows, extra_dns_events=extra_dns_events)
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
        "aggregation_version": aggregation_version,
        **features,
    }
