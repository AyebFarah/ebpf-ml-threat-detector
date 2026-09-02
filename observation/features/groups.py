from __future__ import annotations
from collections import defaultdict
from statistics import mean, stdev

from observation.features.config import (
    WELL_KNOWN_PORT_MAX, HIGH_PORT_MIN, RARE_JA4_THRESHOLD,
    SENSITIVE_TIER1_PREFIXES, SHELL_BINARIES, INTERPRETER_BINARIES,
)
from observation.features.entropy import shannon_entropy
from observation.features.ip_utils import is_private_ip, is_external_ip
from observation.features.string_features import domain_label_stats


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    s = sorted(values)
    return s[int(0.95 * (len(s) - 1))]


def _most_common(values):
    if not values:
        return None
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    return max(counts.items(), key=lambda kv: kv[1])[0]


def _basename(path):
    return path.rsplit("/", 1)[-1] if path else None


def basic_counts(rows, ssh_total) -> dict:
    n = len(rows)
    return {
        "event_count": n,
        "tcp_connect_count": n,
        "tcp_close_count": sum(1 for r in rows if r["tcp_flow_matched"]),
        "dns_query_count": sum(1 for r in rows if r["dns_domain"]),
        "tls_connection_count": sum(1 for r in rows if r["tls_matched"]),
        "http_request_count": sum(1 for r in rows if r["http_host"]),
        "ssh_attempt_count": ssh_total,
    }


def network_topology(rows) -> dict:
    dst_ips = [r["dst_ip"] for r in rows if r["dst_ip"]]
    dst_ports = [r["dst_port"] for r in rows if r["dst_port"] is not None]
    src_ports = {r["src_port"] for r in rows if r["src_port"] is not None}
    ip_counts = defaultdict(int)
    for ip in dst_ips:
        ip_counts[ip] += 1
    port_counts = defaultdict(int)
    for p in dst_ports:
        port_counts[p] += 1
    external_dst = sum(1 for ip in dst_ips if is_external_ip(ip))
    private_dst = sum(1 for ip in dst_ips if is_private_ip(ip))
    well_known = sum(1 for p in dst_ports if p < WELL_KNOWN_PORT_MAX)
    high_ports = sum(1 for p in dst_ports if p >= HIGH_PORT_MIN)

    return {
        "unique_dst_ip_count": len(ip_counts),
        "unique_dst_port_count": len(port_counts),
        "unique_src_port_count": len(src_ports),
        "external_dst_ip_count": external_dst,
        "private_dst_ip_count": private_dst,
        "dst_port_entropy": shannon_entropy(list(port_counts.values())),
        "dst_ip_entropy": shannon_entropy(list(ip_counts.values())),
        "well_known_port_ratio": well_known / len(dst_ports) if dst_ports else None,
        "high_port_ratio": high_ports / len(dst_ports) if dst_ports else None,
        "external_destination_ratio": external_dst / len(dst_ips) if dst_ips else None,
    }


def traffic_volume(rows) -> dict:
    return {
        "total_bytes_in": sum(r["bytes_received"] or 0 for r in rows),
        "total_bytes_out": sum(r["bytes_sent"] or 0 for r in rows),
        "total_packets_in": sum(r["packets_received"] or 0 for r in rows),
        "total_packets_out": sum(r["packets_sent"] or 0 for r in rows),
    }


def flow_dynamics(rows) -> dict:
    n = len(rows)
    durations = [r["flow_duration"] for r in rows if r["flow_duration"] is not None]
    failed = sum(
        1 for r in rows
        if not r["tcp_flow_matched"] or (r["termination_reason"] and "reset" in r["termination_reason"].lower())
    )
    return {
        "mean_flow_duration_sec": mean(durations) if durations else None,
        "max_flow_duration_sec": max(durations) if durations else None,
        "failed_connection_count": failed,
        "failed_connection_ratio": failed / n if n else None,
    }


def rate_and_burstiness(rows, window_start, window_end, traffic: dict) -> dict:
    duration_s = (window_end - window_start).total_seconds() or 1.0
    timestamps = sorted(r["_ts"] for r in rows)
    interarrivals_ms = [
        (timestamps[i] - timestamps[i - 1]).total_seconds() * 1000
        for i in range(1, len(timestamps))
    ]
    return {
        "connections_per_sec": len(rows) / duration_s,
        "bytes_per_sec_in": traffic["total_bytes_in"] / duration_s,
        "bytes_per_sec_out": traffic["total_bytes_out"] / duration_s,
        "packets_per_sec_in": traffic["total_packets_in"] / duration_s,
        "packets_per_sec_out": traffic["total_packets_out"] / duration_s,
        "interarrival_mean_ms": mean(interarrivals_ms) if interarrivals_ms else None,
        "interarrival_std_ms": stdev(interarrivals_ms) if len(interarrivals_ms) > 1 else None,
        "interarrival_p95_ms": _p95(interarrivals_ms),
    }


def dns_features(rows) -> dict:
    domains = [r["dns_domain"] for r in rows if r["dns_domain"]]
    resolved_ips = {r["dns_resolved_ip"] for r in rows if r["dns_resolved_ip"]}
    dns_latencies = [r["dns_latency_ms"] for r in rows if r["dns_latency_ms"] is not None]
    nxdomain = sum(1 for r in rows if r["dns_rcode"] == 3)
    dstats = domain_label_stats(domains)
    return {
        "unique_domain_count": len(set(domains)),
        "nxdomain_count": nxdomain,
        "nxdomain_ratio": nxdomain / len(domains) if domains else None,
        **dstats,
        "unique_resolved_ip_count": len(resolved_ips),
        "dns_response_latency_mean_ms": mean(dns_latencies) if dns_latencies else None,
        "dns_response_latency_p95_ms": _p95(dns_latencies),
    }


def tls_features(rows, ja4_baseline: dict) -> dict:
    import json
    ja4s = [r["tls_ja4"] for r in rows if r["tls_ja4"]]
    snis = [r["tls_sni"] for r in rows if r["tls_sni"]]
    ja4_counts = defaultdict(int)
    for j in ja4s:
        ja4_counts[j] += 1
    tls_versions = defaultdict(int)
    for r in rows:
        if r["tls_version"]:
            tls_versions[r["tls_version"]] += 1
    tls_matched_rows = [r for r in rows if r["tls_matched"]]
    rare_hits = sum(1 for j in ja4s if ja4_baseline.get(j, 0) < RARE_JA4_THRESHOLD)
    most_common_ja4 = _most_common(ja4s)

    return {
        "unique_sni_count": len(set(snis)),
        "missing_sni_count": sum(1 for r in tls_matched_rows if not r["tls_sni"]),
        "missing_sni_ratio": (
                sum(1 for r in tls_matched_rows if not r["tls_sni"]) / len(tls_matched_rows)
        ) if tls_matched_rows else None,
        "unique_ja4_count": len(ja4_counts),
        "ja4_entropy": shannon_entropy(list(ja4_counts.values())),
        "rare_ja4_ratio": rare_hits / len(ja4s) if ja4s else None,
        "tls_version_distribution": json.dumps(tls_versions) if tls_versions else None,
        "most_common_ja4": most_common_ja4,
        "most_common_ja4_count": ja4_counts.get(most_common_ja4, 0) if most_common_ja4 else None,
    }


def http_features(rows) -> dict:
    import json
    http_hosts = {r["http_host"] for r in rows if r["http_host"]}
    http_methods = defaultdict(int)
    for r in rows:
        if r["http_method"]:
            http_methods[r["http_method"]] += 1
    statuses = [r["http_status"] for r in rows if r["http_status"] is not None]
    n = len(statuses) or 1
    path_lengths = [r["http_path_length"] for r in rows if r["http_path_length"] is not None]
    content_lengths = [r["http_content_length"] for r in rows if r["http_content_length"] is not None]

    return {
        "http_unique_host_count": len(http_hosts),
        "http_methods_distribution": json.dumps(http_methods) if http_methods else None,
        "http_status_2xx_ratio": sum(1 for s in statuses if 200 <= s < 300) / n if statuses else None,
        "http_status_4xx_ratio": sum(1 for s in statuses if 400 <= s < 500) / n if statuses else None,
        "http_status_5xx_ratio": sum(1 for s in statuses if 500 <= s < 600) / n if statuses else None,
        "mean_path_length": mean(path_lengths) if path_lengths else None,
        "mean_content_length": mean(content_lengths) if content_lengths else None,
    }


def process_features(rows, depth_calc) -> dict:
    """process_exec_count / unique_binary_count are network-contextualized
    proxies: they only count processes that generated at least one
    correlated network connection in this run. See docs/011."""
    binaries = [r["binary"] for r in rows if r["binary"]]
    exec_ids = list({r["exec_id"] for r in rows if r["exec_id"]})
    shell_spawns = sum(1 for b in binaries if _basename(b) in SHELL_BINARIES)
    interp_spawns = sum(1 for b in binaries if _basename(b) in INTERPRETER_BINARIES)

    return {
        "process_exec_count": len(exec_ids),
        "unique_binary_count": len(set(binaries)),
        "shell_spawn_count": shell_spawns,
        "interpreter_spawn_count": interp_spawns,
        "process_tree_depth_max": depth_calc.max_depth(exec_ids),
    }


def privilege_and_file_features(rows, file_events, privilege_events, window_end) -> dict:
    """Timing features only see privilege/file events already correlated
    to a network connection in this run (±30s window from correlator.py).
    See docs/011 for the honest scope of this."""
    sensitive_touch = sum(
        1 for fe in file_events
        if fe["path"] and any(fe["path"].startswith(p) for p in SENSITIVE_TIER1_PREFIXES)
    )
    sudo_count = sum(1 for pe in privilege_events if pe["event_type"] == "sudo_exec"
                     and pe["detail"] and "sudo" in pe["detail"].lower())
    pkexec_count = sum(1 for pe in privilege_events if pe["detail"] and "pkexec" in (pe["detail"] or "").lower())
    su_count = sum(1 for pe in privilege_events if pe["detail"] and pe["detail"].strip().startswith("su "))
    capability_count = sum(1 for pe in privilege_events if pe["event_type"] == "capability_use")

    priv_ts = [pe["_ts"] for pe in privilege_events if pe["_ts"]]
    file_ts = [fe["_ts"] for fe in file_events if fe["_ts"]]
    net_ts = [r["_ts"] for r in rows]

    return {
        "sensitive_file_event_count": sensitive_touch,
        "privilege_event_count": len(privilege_events),
        "sudo_exec_count": sudo_count,
        "pkexec_count": pkexec_count,
        "su_exec_count": su_count,
        "capability_event_count": capability_count,
        "seconds_since_last_privilege_event": (
            (window_end - max(priv_ts)).total_seconds() if priv_ts else None
        ),
        "seconds_since_last_sensitive_file_access": (
            (window_end - max(file_ts)).total_seconds() if file_ts else None
        ),
        "network_events_after_privilege_event": (
            sum(1 for t in net_ts if t > max(priv_ts)) if priv_ts else None
        ),
        "network_events_after_sensitive_file_access": (
            sum(1 for t in net_ts if t > max(file_ts)) if file_ts else None
        ),
    }


def ssh_features(ssh_sessions_in_window) -> dict:
    ssh_success = sum(1 for s in ssh_sessions_in_window if s["auth_success_ts"])
    ssh_failure = sum(1 for s in ssh_sessions_in_window if not s["auth_success_ts"])
    durations = [s["session_duration_seconds"] for s in ssh_sessions_in_window if s["session_duration_seconds"]]
    total = len(ssh_sessions_in_window)
    return {
        "ssh_success_count": ssh_success,
        "ssh_failure_count": ssh_failure,
        "ssh_failure_ratio": ssh_failure / total if total else None,
        "ssh_session_count": total,
        "mean_ssh_session_duration_sec": mean(durations) if durations else None,
    }