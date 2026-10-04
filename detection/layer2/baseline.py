"""
Graph statistics: a handful of numbers that describe the SHAPE of one graph.
A LightGBM trained on these is the ablation that answers: does a neural
network reading the full graph beat simple structural counts?
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components

from detection.layer2.schema import (
    COL_ENTROPY, COL_EXTERNAL, COL_LOG_COUNT, COL_LOG_LEN, COL_WELLKNOWN, NODE_KINDS,
)

STAT_COLUMNS = [
    "n_nodes", "n_edges", "n_process", "n_remote_ip", "n_domain", "n_file", "n_port",
    "density", "mean_degree", "max_degree", "max_process_fanout", "max_ip_port_fanout",
    "max_port_log_count", "n_components", "external_ip_ratio", "mean_domain_entropy",
    "max_domain_log_length", "wellknown_port_ratio",
]


def _max_fanout(ei, n, from_mask, to_mask) -> int:
    """Largest number of neighbours of kind `to` that one node of kind `from` has."""
    hits = from_mask[ei[0]] & to_mask[ei[1]]
    return int(np.bincount(ei[0][hits], minlength=n).max()) if hits.any() else 0


def graph_stats(g) -> dict:
    x, ei = g.x.numpy(), g.edge_index.numpy()
    n, e = x.shape[0], ei.shape[1] // 2
    kinds = x[:, :len(NODE_KINDS)].argmax(axis=1)
    is_proc = kinds == NODE_KINDS.index("process")
    is_ip = kinds == NODE_KINDS.index("remote_ip")
    is_dom = kinds == NODE_KINDS.index("domain")
    is_file = kinds == NODE_KINDS.index("file")
    is_port = kinds == NODE_KINDS.index("port")

    if ei.shape[1]:
        degree = np.bincount(ei[0], minlength=n)
        proc_fanout = _max_fanout(ei, n, is_proc, is_ip)
        ip_port_fanout = _max_fanout(ei, n, is_ip, is_port)
        adj = csr_matrix((np.ones(ei.shape[1]), (ei[0], ei[1])), shape=(n, n))
        components = int(connected_components(adj, directed=False)[0])
    else:
        degree, proc_fanout, ip_port_fanout, components = np.zeros(n), 0, 0, n

    return {
        "n_nodes": n, "n_edges": e,
        "n_process": int(is_proc.sum()), "n_remote_ip": int(is_ip.sum()),
        "n_domain": int(is_dom.sum()), "n_file": int(is_file.sum()), "n_port": int(is_port.sum()),
        "density": 2 * e / (n * (n - 1)) if n > 1 else 0.0,
        "mean_degree": float(degree.mean()), "max_degree": int(degree.max()),
        "max_process_fanout": proc_fanout, "max_ip_port_fanout": ip_port_fanout,
        "max_port_log_count": float(x[is_port, COL_LOG_COUNT].max()) if is_port.any() else 0.0,
        "n_components": components,
        "external_ip_ratio": float(x[is_ip, COL_EXTERNAL].mean()) if is_ip.any() else 0.0,
        "mean_domain_entropy": float(x[is_dom, COL_ENTROPY].mean()) if is_dom.any() else 0.0,
        "max_domain_log_length": float(x[is_dom, COL_LOG_LEN].max()) if is_dom.any() else 0.0,
        "wellknown_port_ratio": float(x[is_ip, COL_WELLKNOWN].mean()) if is_ip.any() else 0.0,
    }


def stats_frame(graphs) -> pd.DataFrame:
    return pd.DataFrame([graph_stats(g) for g in graphs], columns=STAT_COLUMNS)