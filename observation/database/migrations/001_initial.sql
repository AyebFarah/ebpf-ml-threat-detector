CREATE TABLE IF NOT EXISTS observation_runs (
        run_id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        status TEXT NOT NULL DEFAULT 'running',
        correlated_events_count INTEGER NOT NULL DEFAULT 0,
        ssh_sessions_count INTEGER NOT NULL DEFAULT 0,
        source_correlated_file TEXT,
        source_ssh_sessions_file TEXT
);

-- =====================================================================
-- correlated_events: the central, ML-oriented table. One row per
-- tcp_connect. Holds ONLY compact, frequently-queried features -- match
-- flags, methods, time deltas, activity counts. No per-signal detail
-- fields live here; those belong in the specialized *_observations
-- tables below, joined on correlated_event_id.
-- =====================================================================
CREATE TABLE IF NOT EXISTS correlated_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES observation_runs(run_id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    transport TEXT,
    direction TEXT,
    process_pid INTEGER,
    process_name TEXT,

    dns_matched INTEGER NOT NULL DEFAULT 0,
    dns_method TEXT,
    dns_time_delta_ms INTEGER,
    dns_response_latency_ms REAL,

    tls_matched INTEGER NOT NULL DEFAULT 0,
    tls_method TEXT,
    tls_time_delta_ms INTEGER,

    ssh_matched INTEGER NOT NULL DEFAULT 0,
    ssh_method TEXT,
    ssh_time_delta_ms INTEGER,

    tcp_flow_matched INTEGER NOT NULL DEFAULT 0,
    tcp_flow_method TEXT,
    tcp_flow_time_delta_ms INTEGER,

    http_matched INTEGER NOT NULL DEFAULT 0,
    http_method TEXT,
    http_time_delta_ms INTEGER,

    process_context_matched INTEGER NOT NULL DEFAULT 0,
    process_context_method TEXT,

    file_activity_count INTEGER NOT NULL DEFAULT 0,
    file_activity_method TEXT,
    privilege_activity_count INTEGER NOT NULL DEFAULT 0,
    privilege_activity_method TEXT,

    raw_json TEXT NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_correlated_events_run_id ON correlated_events(run_id);
CREATE INDEX IF NOT EXISTS idx_correlated_events_timestamp ON correlated_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_correlated_events_dst_ip ON correlated_events(dst_ip);
CREATE INDEX IF NOT EXISTS idx_correlated_events_process_pid ON correlated_events(process_pid);

-- =====================================================================
-- process_observations: detailed process-lineage data for a matched
-- connection. Split out from correlated_events per the hybrid rule --
-- exec_id/parent_binary/arguments/uid/cwd are rich, variable-length
-- observation data, not compact match features.
-- =====================================================================
CREATE TABLE IF NOT EXISTS process_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlated_event_id INTEGER NOT NULL REFERENCES correlated_events(id) ON DELETE CASCADE,
    timestamp TEXT,
    exec_id TEXT,
    parent_exec_id TEXT,
    parent_binary TEXT,
    arguments TEXT,
    uid INTEGER,
    cwd TEXT,
    raw_json TEXT
    );

CREATE INDEX IF NOT EXISTS idx_process_observations_correlated_event_id ON process_observations(correlated_event_id);
CREATE INDEX IF NOT EXISTS idx_process_observations_exec_id ON process_observations(exec_id);

-- =====================================================================
-- dns_observations
-- =====================================================================
CREATE TABLE IF NOT EXISTS dns_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlated_event_id INTEGER NOT NULL REFERENCES correlated_events(id) ON DELETE CASCADE,
    timestamp TEXT,
    query_name TEXT,
    query_type INTEGER,
    transaction_id INTEGER,
    rcode INTEGER,
    answer_count INTEGER,
    resolved_ip TEXT,
    ttl INTEGER,
    response_latency_ms REAL,
    raw_json TEXT
    );

CREATE INDEX IF NOT EXISTS idx_dns_observations_correlated_event_id ON dns_observations(correlated_event_id);
CREATE INDEX IF NOT EXISTS idx_dns_observations_query_name ON dns_observations(query_name);
CREATE INDEX IF NOT EXISTS idx_dns_observations_resolved_ip ON dns_observations(resolved_ip);

-- =====================================================================
-- tls_observations
-- =====================================================================
CREATE TABLE IF NOT EXISTS tls_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlated_event_id INTEGER NOT NULL REFERENCES correlated_events(id) ON DELETE CASCADE,
    timestamp TEXT,
    sni TEXT,
    ja4 TEXT,
    tls_version TEXT,
    raw_json TEXT
    );

CREATE INDEX IF NOT EXISTS idx_tls_observations_correlated_event_id ON tls_observations(correlated_event_id);
CREATE INDEX IF NOT EXISTS idx_tls_observations_sni ON tls_observations(sni);
CREATE INDEX IF NOT EXISTS idx_tls_observations_ja4 ON tls_observations(ja4);

-- =====================================================================
-- tcp_flow_observations
-- =====================================================================
CREATE TABLE IF NOT EXISTS tcp_flow_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlated_event_id INTEGER NOT NULL REFERENCES correlated_events(id) ON DELETE CASCADE,
    start_ts TEXT,
    end_ts TEXT,
    duration_seconds REAL,
    handshake_completed INTEGER,
    handshake_rtt_ms REAL,
    termination_reason TEXT,
    packets_out INTEGER,
    packets_in INTEGER,
    bytes_out INTEGER,
    bytes_in INTEGER,
    retransmissions INTEGER,
    raw_json TEXT
    );

CREATE INDEX IF NOT EXISTS idx_tcp_flow_observations_correlated_event_id ON tcp_flow_observations(correlated_event_id);

-- =====================================================================
-- http_observations
-- =====================================================================
CREATE TABLE IF NOT EXISTS http_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlated_event_id INTEGER NOT NULL REFERENCES correlated_events(id) ON DELETE CASCADE,
    request_timestamp TEXT,
    response_timestamp TEXT,
    method TEXT,
    host TEXT,
    path_hash TEXT,
    path_length INTEGER,
    user_agent_hash TEXT,
    status_code INTEGER,
    content_type TEXT,
    content_length INTEGER,
    raw_json TEXT
    );

CREATE INDEX IF NOT EXISTS idx_http_observations_correlated_event_id ON http_observations(correlated_event_id);
CREATE INDEX IF NOT EXISTS idx_http_observations_host ON http_observations(host);
CREATE INDEX IF NOT EXISTS idx_http_observations_status_code ON http_observations(status_code);

-- =====================================================================
-- file_activity_events
-- =====================================================================
CREATE TABLE IF NOT EXISTS file_activity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlated_event_id INTEGER NOT NULL REFERENCES correlated_events(id) ON DELETE CASCADE,
    timestamp TEXT,
    path TEXT,
    operations TEXT
    );

CREATE INDEX IF NOT EXISTS idx_file_activity_correlated_event_id ON file_activity_events(correlated_event_id);
CREATE INDEX IF NOT EXISTS idx_file_activity_path ON file_activity_events(path);

-- =====================================================================
-- privilege_activity_events
-- =====================================================================
CREATE TABLE IF NOT EXISTS privilege_activity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlated_event_id INTEGER NOT NULL REFERENCES correlated_events(id) ON DELETE CASCADE,
    timestamp TEXT,
    event_type TEXT,
    detail TEXT
    );

CREATE INDEX IF NOT EXISTS idx_privilege_activity_correlated_event_id ON privilege_activity_events(correlated_event_id);

-- =====================================================================
-- ssh_sessions: independent higher-level entity
-- =====================================================================
CREATE TABLE IF NOT EXISTS ssh_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES observation_runs(run_id) ON DELETE CASCADE,
    session_key TEXT,
    username TEXT,
    src_ip TEXT,
    src_port INTEGER,
    pid INTEGER,
    earliest_event_ts TEXT,
    auth_success_ts TEXT,
    auth_method TEXT,
    session_opened_ts TEXT,
    session_closed_ts TEXT,
    session_duration_seconds REAL,
    disconnected_ts TEXT,
    tcp_connect_matched INTEGER NOT NULL DEFAULT 0,
    tcp_connect_dst_ip TEXT,
    tcp_connect_time_delta_ms INTEGER,
    tcp_close_matched INTEGER NOT NULL DEFAULT 0,
    tcp_close_timestamp TEXT,
    connection_duration_seconds REAL,
    execve_matched INTEGER NOT NULL DEFAULT 0,
    execve_binary TEXT,
    execve_timestamp TEXT,
    raw_json TEXT NOT NULL
    );

CREATE INDEX IF NOT EXISTS idx_ssh_sessions_run_id ON ssh_sessions(run_id);
CREATE INDEX IF NOT EXISTS idx_ssh_sessions_session_key ON ssh_sessions(session_key);