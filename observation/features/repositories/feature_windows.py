from __future__ import annotations
import sqlite3

_COLUMNS = [
    "run_id", "window_start_ts", "window_end_ts", "entity_type", "entity_id",
    "label", "scenario", "attack_family", "attack_technique",
    "feature_version", "aggregation_version",
    "event_count", "tcp_connect_count", "tcp_close_count", "dns_query_count",
    "tls_connection_count", "http_request_count", "ssh_attempt_count",
    "unique_dst_ip_count", "unique_dst_port_count", "unique_src_port_count",
    "external_dst_ip_count", "private_dst_ip_count",
    "total_bytes_in", "total_bytes_out", "total_packets_in", "total_packets_out",
    "mean_flow_duration_sec", "max_flow_duration_sec",
    "failed_connection_count", "failed_connection_ratio",
    "connections_per_sec", "bytes_per_sec_in", "bytes_per_sec_out",
    "packets_per_sec_in", "packets_per_sec_out",
    "interarrival_mean_ms", "interarrival_std_ms", "interarrival_p95_ms",
    "dst_port_entropy", "dst_ip_entropy", "well_known_port_ratio",
    "high_port_ratio", "external_destination_ratio",
    "unique_domain_count", "nxdomain_count", "nxdomain_ratio",
    "mean_domain_length", "max_domain_length", "subdomain_depth_mean",
    "unique_resolved_ip_count", "dns_response_latency_mean_ms", "dns_response_latency_p95_ms",
    "mean_label_length", "max_label_length", "domain_label_entropy_mean",
    "base32_like_ratio", "base64_like_ratio", "hex_like_ratio",
    "unique_sni_count", "missing_sni_count", "missing_sni_ratio",
    "unique_ja4_count", "ja4_entropy", "rare_ja4_ratio",
    "tls_version_distribution", "most_common_ja4", "most_common_ja4_count",
    "http_unique_host_count", "http_methods_distribution",
    "http_status_2xx_ratio", "http_status_4xx_ratio", "http_status_5xx_ratio",
    "mean_path_length", "mean_content_length",
    "process_exec_count", "unique_binary_count", "shell_spawn_count",
    "interpreter_spawn_count", "process_tree_depth_max",
    "sensitive_file_event_count", "privilege_event_count",
    "sudo_exec_count", "pkexec_count", "su_exec_count", "capability_event_count",
    "seconds_since_last_privilege_event", "seconds_since_last_sensitive_file_access",
    "network_events_after_privilege_event", "network_events_after_sensitive_file_access",
    "ssh_success_count", "ssh_failure_count", "ssh_failure_ratio",
    "ssh_session_count", "mean_ssh_session_duration_sec",
    "contributing_event_ids",
]


class FeatureWindowsRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def insert_many(self, windows: list[dict]) -> int:
        placeholders = ", ".join(f":{c}" for c in _COLUMNS)
        col_list = ", ".join(_COLUMNS)
        sql = f"INSERT INTO feature_windows ({col_list}) VALUES ({placeholders})"
        for w in windows:
            self.conn.execute(sql, {c: w.get(c) for c in _COLUMNS})
        return len(windows)

    def delete_for_run(self, run_id: int) -> int:
        cur = self.conn.execute("DELETE FROM feature_windows WHERE run_id = ?", (run_id,))
        return cur.rowcount

    def upsert_for_run(self, run_id: int, windows: list[dict]) -> int:
        """Replace all feature_windows rows for run_id atomically, nested
        safely inside the outer connect() transaction via SAVEPOINT"""
        self.conn.execute("SAVEPOINT feature_upsert")
        try:
            deleted = self.delete_for_run(run_id)
            print(f"[features] deleting existing windows for run_id={run_id} ({deleted} removed)")
            count = self.insert_many(windows)
            print(f"[features] inserting {count} windows for run_id={run_id}")
            self.conn.execute("RELEASE SAVEPOINT feature_upsert")
            return count
        except Exception:
            self.conn.execute("ROLLBACK TO SAVEPOINT feature_upsert")
            raise