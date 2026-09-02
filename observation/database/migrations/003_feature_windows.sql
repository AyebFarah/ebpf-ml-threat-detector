DROP TABLE IF EXISTS feature_windows;

CREATE TABLE feature_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES observation_runs(run_id) ON DELETE CASCADE,
    window_start_ts TEXT NOT NULL,
    window_end_ts TEXT NOT NULL,

    entity_type TEXT NOT NULL,      -- 'host' | 'process' | 'flow'
    entity_id TEXT NOT NULL,

    label INTEGER,                  -- 0=benign, 1=malicious
    scenario TEXT,
    attack_family TEXT,
    attack_technique TEXT,

    feature_version TEXT NOT NULL,
    aggregation_version TEXT NOT NULL,

    event_count INTEGER NOT NULL DEFAULT 0,
    tcp_connect_count INTEGER NOT NULL DEFAULT 0,
    tcp_close_count INTEGER NOT NULL DEFAULT 0,
    dns_query_count INTEGER NOT NULL DEFAULT 0,
    tls_connection_count INTEGER NOT NULL DEFAULT 0,
    http_request_count INTEGER NOT NULL DEFAULT 0,
    ssh_attempt_count INTEGER NOT NULL DEFAULT 0,

    unique_dst_ip_count INTEGER NOT NULL DEFAULT 0,
    unique_dst_port_count INTEGER NOT NULL DEFAULT 0,
    unique_src_port_count INTEGER NOT NULL DEFAULT 0,
    external_dst_ip_count INTEGER NOT NULL DEFAULT 0,
    private_dst_ip_count INTEGER NOT NULL DEFAULT 0,

    total_bytes_in INTEGER NOT NULL DEFAULT 0,
    total_bytes_out INTEGER NOT NULL DEFAULT 0,
    total_packets_in INTEGER NOT NULL DEFAULT 0,
    total_packets_out INTEGER NOT NULL DEFAULT 0,

    mean_flow_duration_sec REAL,
    max_flow_duration_sec REAL,
    failed_connection_count INTEGER NOT NULL DEFAULT 0,
    failed_connection_ratio REAL,

    connections_per_sec REAL,
    bytes_per_sec_in REAL,
    bytes_per_sec_out REAL,
    packets_per_sec_in REAL,
    packets_per_sec_out REAL,
    interarrival_mean_ms REAL,
    interarrival_std_ms REAL,
    interarrival_p95_ms REAL,

    dst_port_entropy REAL,
    dst_ip_entropy REAL,
    well_known_port_ratio REAL,
    high_port_ratio REAL,
    external_destination_ratio REAL,

    unique_domain_count INTEGER NOT NULL DEFAULT 0,
    nxdomain_count INTEGER NOT NULL DEFAULT 0,
    nxdomain_ratio REAL,
    mean_domain_length REAL,
    max_domain_length INTEGER,
    subdomain_depth_mean REAL,
    unique_resolved_ip_count INTEGER NOT NULL DEFAULT 0,
    dns_response_latency_mean_ms REAL,
    dns_response_latency_p95_ms REAL,

    mean_label_length REAL,
    max_label_length INTEGER,
    domain_label_entropy_mean REAL,
    base32_like_ratio REAL,
    base64_like_ratio REAL,
    hex_like_ratio REAL,

    unique_sni_count INTEGER NOT NULL DEFAULT 0,
    missing_sni_count INTEGER NOT NULL DEFAULT 0,
    missing_sni_ratio REAL,
    unique_ja4_count INTEGER NOT NULL DEFAULT 0,
    ja4_entropy REAL,
    rare_ja4_ratio REAL,
    tls_version_distribution TEXT,
    most_common_ja4 TEXT,
    most_common_ja4_count INTEGER,

    http_unique_host_count INTEGER NOT NULL DEFAULT 0,
    http_methods_distribution TEXT,
    http_status_2xx_ratio REAL,
    http_status_4xx_ratio REAL,
    http_status_5xx_ratio REAL,
    mean_path_length REAL,
    mean_content_length REAL,

    process_exec_count INTEGER NOT NULL DEFAULT 0,
    unique_binary_count INTEGER NOT NULL DEFAULT 0,
    shell_spawn_count INTEGER NOT NULL DEFAULT 0,
    interpreter_spawn_count INTEGER NOT NULL DEFAULT 0,
    process_tree_depth_max INTEGER,   -- NULL in v1, see limitations

    sensitive_file_event_count INTEGER NOT NULL DEFAULT 0,
    privilege_event_count INTEGER NOT NULL DEFAULT 0,
    sudo_exec_count INTEGER NOT NULL DEFAULT 0,
    pkexec_count INTEGER NOT NULL DEFAULT 0,
    su_exec_count INTEGER NOT NULL DEFAULT 0,
    capability_event_count INTEGER NOT NULL DEFAULT 0,

    seconds_since_last_privilege_event REAL,
    seconds_since_last_sensitive_file_access REAL,
    network_events_after_privilege_event INTEGER,
    network_events_after_sensitive_file_access INTEGER,

    ssh_success_count INTEGER NOT NULL DEFAULT 0,
    ssh_failure_count INTEGER NOT NULL DEFAULT 0,
    ssh_failure_ratio REAL,
    ssh_session_count INTEGER NOT NULL DEFAULT 0,
    mean_ssh_session_duration_sec REAL,

    contributing_event_ids TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_feature_windows_run_id ON feature_windows(run_id);
CREATE INDEX idx_feature_windows_entity ON feature_windows(entity_type, entity_id);
CREATE INDEX idx_feature_windows_timestamp ON feature_windows(window_start_ts, window_end_ts);
CREATE INDEX idx_feature_windows_label ON feature_windows(label);