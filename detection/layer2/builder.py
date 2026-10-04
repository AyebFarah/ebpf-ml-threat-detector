"""
Turns observations into one graph per host feature window.

Evidence comes from three places, because Layer 1 uses all three:
  1. correlated_events (tcp_connect with process, DNS, TLS, file context)
  2. tcp_flows_raw     (flows, including inbound attack traffic)
  3. dns_events_raw    (every DNS query, selected by the window's time range)

The window ids in feature_windows.contributing_event_ids mix integers
(correlated_events) and strings like "flow_raw_149469" (tcp_flows_raw).
"""
from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sqlalchemy import text
from torch_geometric.data import Data

from detection.config import DB_PATH
from detection.data.extract import load_feature_windows
from detection.layer2.dataset import save_snapshot
from detection.layer2.schema import (
    COL_ENTROPY, COL_EXTERNAL, COL_LOG_COUNT, COL_LOG_LEN, COL_WELLKNOWN,
    GRAPH_SCHEMA_VERSION, NODE_FEATURE_NAMES, NODE_KINDS, is_external_ip, text_entropy,
)
from observation.database.connection import get_engine

EVENT_SQL = text("""
SELECT ce.id AS event_id, ce.timestamp AS timestamp, ce.dst_ip AS dst_ip, ce.dst_port AS dst_port,
       ce.process_pid AS process_pid, ce.process_name AS process_name,
       p.exec_id AS exec_id, p.parent_exec_id AS parent_exec_id,
       d.query_name AS query_name, t.sni AS sni
FROM correlated_events ce
LEFT JOIN process_observations p ON p.correlated_event_id = ce.id
LEFT JOIN dns_observations d ON d.correlated_event_id = ce.id
LEFT JOIN tls_observations t ON t.correlated_event_id = ce.id
WHERE ce.run_id = :run_id
""")

FILE_SQL = text("""
SELECT f.correlated_event_id AS event_id, f.path AS path
FROM file_activity_events f
JOIN correlated_events ce ON ce.id = f.correlated_event_id
WHERE ce.run_id = :run_id
""")

FLOW_SQL = text("""
SELECT id AS flow_id, src_ip, dst_ip, dst_port, direction, start_ts
FROM tcp_flows_raw
WHERE run_id = :run_id
""")

DNS_SQL = text("""
SELECT timestamp, query_name
FROM dns_events_raw
WHERE run_id = :run_id AND event_type = 'dns_query' AND query_name IS NOT NULL
""")


class _Registry:
    """Collects nodes and edges while we walk through the evidence of one window."""

    def __init__(self):
        self.index: dict = {}
        self.kinds, self.names, self.counts = [], [], []
        self.port_hits, self.wellknown_hits = [], []
        self.edges: set = set()

    def node(self, kind: str, key: str, name: str | None = None, port=None) -> int:
        ident = (kind, key)
        if ident not in self.index:
            self.index[ident] = len(self.kinds)
            self.kinds.append(kind)
            self.names.append(str(name if name is not None else key))
            self.counts.append(0)
            self.port_hits.append(0)
            self.wellknown_hits.append(0)
        i = self.index[ident]
        self.counts[i] += 1
        if port is not None and pd.notna(port):
            self.port_hits[i] += 1
            self.wellknown_hits[i] += int(int(port) < 1024)
        return i

    def link(self, a: int, b: int) -> None:
        if a != b:
            self.edges.add((min(a, b), max(a, b)))


def build_graph(events: pd.DataFrame, files: pd.DataFrame, label: int,
                flows: pd.DataFrame | None = None, dns: pd.DataFrame | None = None) -> Data:
    reg = _Registry()
    host = reg.node("host", "host")          # always present, so no graph is ever empty
    process_of_event: dict = {}

    # 1. tcp_connect events with their process, DNS and TLS context
    for r in events.itertuples(index=False):
        proc_name = r.process_name if pd.notna(r.process_name) else "unknown"
        if pd.notna(r.exec_id):
            proc_key = r.exec_id
        elif pd.notna(r.process_pid):
            proc_key = f"pid:{int(r.process_pid)}"
        else:
            proc_key = f"unknown:{proc_name}"
        proc = reg.node("process", proc_key, name=proc_name)
        process_of_event[r.event_id] = proc
        reg.link(host, proc)

        if pd.notna(r.parent_exec_id):
            reg.link(reg.node("process", r.parent_exec_id, name="parent_process"), proc)

        ip = None
        if pd.notna(r.dst_ip):
            ip = reg.node("remote_ip", r.dst_ip, port=r.dst_port)
            reg.link(proc, ip)

        domain_name = r.query_name if pd.notna(r.query_name) else (r.sni if pd.notna(r.sni) else None)
        if domain_name:
            dom = reg.node("domain", str(domain_name).lower())
            reg.link(proc, dom)
            if ip is not None:
                reg.link(dom, ip)

    # 2. raw flows: remote IP, the service port involved, and the host
    if flows is not None:
        for r in flows.itertuples(index=False):
            remote = r.src_ip if str(r.direction) == "inbound" else r.dst_ip
            if pd.isna(remote):
                continue
            ip = reg.node("remote_ip", remote, port=r.dst_port)
            if pd.notna(r.dst_port):
                port_no = int(r.dst_port)
                port = reg.node("port", f"{r.direction}:{port_no}", name=str(port_no), port=port_no)
                reg.link(ip, port)
                reg.link(port, host)
            else:
                reg.link(ip, host)

    # 3. raw DNS queries: every queried name hangs off the host
    if dns is not None:
        for r in dns.itertuples(index=False):
            reg.link(host, reg.node("domain", str(r.query_name).lower()))

    # 4. sensitive files touched by a process
    for r in files.itertuples(index=False):
        proc = process_of_event.get(r.event_id)
        if proc is not None and pd.notna(r.path):
            reg.link(proc, reg.node("file", r.path))

    return _to_data(reg, label)


def _to_data(reg: _Registry, label: int) -> Data:
    n = len(reg.kinds)
    x = np.zeros((n, len(NODE_FEATURE_NAMES)), dtype=np.float32)
    for i in range(n):
        x[i, NODE_KINDS.index(reg.kinds[i])] = 1.0
        x[i, COL_LOG_COUNT] = math.log1p(reg.counts[i])
        x[i, COL_EXTERNAL] = float(reg.kinds[i] == "remote_ip" and is_external_ip(reg.names[i]))
        x[i, COL_ENTROPY] = text_entropy(reg.names[i])
        x[i, COL_LOG_LEN] = math.log1p(len(reg.names[i]))
        x[i, COL_WELLKNOWN] = reg.wellknown_hits[i] / reg.port_hits[i] if reg.port_hits[i] else 0.0

    if reg.edges:
        pairs = sorted(reg.edges)
        src = [a for a, b in pairs] + [b for a, b in pairs]   # both directions:
        dst = [b for a, b in pairs] + [a for a, b in pairs]   # the graph is undirected
        edge_index = torch.tensor([src, dst], dtype=torch.long)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)
    return Data(x=torch.from_numpy(x), edge_index=edge_index, y=torch.tensor([float(label)]))


def _parse_tokens(raw):
    """'[12, "flow_raw_5"]' becomes ([12], [5]). Returns None if unreadable."""
    if raw is None or (isinstance(raw, float) and pd.isna(raw)):
        return None
    try:
        values = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(values, list):
        return None
    event_ids, flow_ids = [], []
    for v in values:
        if isinstance(v, int):
            event_ids.append(v)
            continue
        s = str(v)
        digits = s[len(s.rstrip("0123456789")):]
        prefix = s[:len(s) - len(digits)].rstrip("_")
        if not digits:
            continue
        if prefix == "flow_raw":
            flow_ids.append(int(digits))
        elif prefix == "":
            event_ids.append(int(digits))
    return event_ids, flow_ids


def _to_ts(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, utc=True, format="ISO8601")


class _RunData:
    """Everything one run contributes, loaded once and sliced per window."""

    def __init__(self, engine, run_id: int):
        p = {"run_id": int(run_id)}
        self.events = (pd.read_sql_query(EVENT_SQL, engine, params=p)
                       .drop_duplicates("event_id").reset_index(drop=True))
        self.events["ts"] = _to_ts(self.events["timestamp"])
        self.events_by_id = self.events.set_index("event_id", drop=False)
        self.files = pd.read_sql_query(FILE_SQL, engine, params=p)
        self.flows = (pd.read_sql_query(FLOW_SQL, engine, params=p)
                      .drop_duplicates("flow_id").reset_index(drop=True))
        self.flows["ts"] = _to_ts(self.flows["start_ts"])
        self.flows_by_id = self.flows.set_index("flow_id", drop=False)
        self.dns = pd.read_sql_query(DNS_SQL, engine, params=p)
        self.dns["ts"] = _to_ts(self.dns["timestamp"])


def _in_range(frame: pd.DataFrame, start, end) -> pd.DataFrame:
    return frame[(frame["ts"] >= start) & (frame["ts"] < end)]


def _window_parts(w, run: _RunData):
    start = pd.to_datetime(w.window_start_ts, utc=True)
    end = pd.to_datetime(w.window_end_ts, utc=True)
    tokens = _parse_tokens(w.contributing_event_ids)

    if tokens is None:                                   # unreadable list: use time only
        ev, fl = _in_range(run.events, start, end), _in_range(run.flows, start, end)
    else:
        event_ids, flow_ids = tokens
        ev = run.events_by_id.loc[run.events_by_id.index.intersection(event_ids)]
        fl = run.flows_by_id.loc[run.flows_by_id.index.intersection(flow_ids)]
        if event_ids and ev.empty:                       # stale ids after the merge: use time
            ev = _in_range(run.events, start, end)
        if flow_ids and fl.empty:
            fl = _in_range(run.flows, start, end)

    return ev.reset_index(drop=True), fl.reset_index(drop=True), _in_range(run.dns, start, end)


def build_all(db_path=DB_PATH):
    windows = load_feature_windows(db_path, "host")
    if windows.empty:
        raise SystemExit("[builder] no host windows found, run the feature pipeline first")

    engine = get_engine(Path(db_path))
    graphs, rows = [], []
    try:
        for run_id, run_windows in windows.groupby("run_id"):
            run = _RunData(engine, run_id)
            for w in run_windows.sort_values("window_start_ts").itertuples(index=False):
                ev, fl, dn = _window_parts(w, run)
                files = run.files[run.files["event_id"].isin(ev["event_id"])]
                g = build_graph(ev, files, int(w.label), flows=fl, dns=dn)
                graphs.append(g)
                rows.append({
                    "window_id": int(w.id), "run_id": int(w.run_id), "entity_id": w.entity_id,
                    "window_start_ts": w.window_start_ts, "window_end_ts": w.window_end_ts,
                    "label": int(w.label), "scenario": w.scenario, "attack_family": w.attack_family,
                    "n_nodes": int(g.x.shape[0]), "n_edges": int(g.edge_index.shape[1] // 2),
                    "n_tcp_connect": int(len(ev)), "n_flows": int(len(fl)), "n_dns": int(len(dn)),
                    "n_events": int(len(ev) + len(fl) + len(dn)),
                })
    finally:
        engine.dispose()
    return windows, graphs, pd.DataFrame(rows)


def _report(index: pd.DataFrame) -> None:
    print(f"[builder] {len(index)} graphs from {index.run_id.nunique()} runs")
    print(f"[builder] attack graphs: {int((index.label == 1).sum())}, "
          f"benign graphs: {int((index.label == 0).sum())}")
    print("[builder] median nodes per graph, by scenario:")
    print(index.groupby("scenario")["n_nodes"].median().round(1).to_string())
    print("[builder] share of empty windows, by scenario:")
    print(index.assign(empty=index.n_events == 0).groupby("scenario")["empty"].mean().round(2).to_string())
    empty = float((index.n_events == 0).mean())
    print(f"[builder] windows with zero evidence: {empty:.1%}")
    if empty > 0.5:
        print("[builder] WARNING: more than half of the graphs are empty. Check the id formats.")


def build_and_save(db_path=DB_PATH):
    windows, graphs, index = build_all(db_path)
    _report(index)
    path = save_snapshot(graphs, index, {
        "db_path": str(db_path),
        "graph_schema_version": GRAPH_SCHEMA_VERSION,
        "node_feature_names": NODE_FEATURE_NAMES,
        "feature_version": sorted(windows["feature_version"].dropna().unique().tolist()),
        "aggregation_version": sorted(windows["aggregation_version"].dropna().unique().tolist()),
    })
    print(f"[builder] snapshot written to {path}")
    return path