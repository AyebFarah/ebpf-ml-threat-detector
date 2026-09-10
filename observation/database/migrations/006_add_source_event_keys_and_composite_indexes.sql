ALTER TABLE file_activity_events ADD COLUMN source_event_key TEXT;
ALTER TABLE privilege_activity_events ADD COLUMN source_event_key TEXT;
CREATE INDEX idx_correlated_events_run_timestamp ON correlated_events(run_id, timestamp);
ALTER TABLE feature_windows ADD COLUMN total_flow_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE tcp_flow_observations ADD COLUMN duration_ms INTEGER;