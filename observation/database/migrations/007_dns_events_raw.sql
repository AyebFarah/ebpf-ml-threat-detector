CREATE TABLE dns_events_raw (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL REFERENCES observation_runs(run_id) ON DELETE CASCADE,
        dedup_key TEXT NOT NULL,
        timestamp TEXT,
        event_type TEXT,        -- 'dns_query' or 'dns_response'
        src_ip TEXT,
        dst_ip TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        transport TEXT,
        direction TEXT,
        query_name TEXT,
        query_type INTEGER,
        transaction_id INTEGER,
        rcode INTEGER,
        answer_count INTEGER,
        resolved_ip TEXT,
        ttl INTEGER,
        raw_json TEXT,
        UNIQUE(run_id, dedup_key)
);
CREATE INDEX idx_dns_events_raw_run_id ON dns_events_raw(run_id);
CREATE INDEX idx_dns_events_raw_query_name ON dns_events_raw(query_name);