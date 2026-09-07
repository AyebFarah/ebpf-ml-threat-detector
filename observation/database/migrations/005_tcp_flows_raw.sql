CREATE TABLE tcp_flows_raw (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES observation_runs(run_id) ON DELETE CASCADE,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    transport TEXT,
    direction TEXT,
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
CREATE INDEX idx_tcp_flows_raw_run_id ON tcp_flows_raw(run_id);