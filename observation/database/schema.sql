CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL, 
	CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
CREATE TABLE observation_runs (
	run_id INTEGER NOT NULL, 
	started_at TEXT NOT NULL, 
	ended_at TEXT, 
	status TEXT NOT NULL, 
	correlated_events_count INTEGER NOT NULL, 
	ssh_sessions_count INTEGER NOT NULL, 
	source_correlated_file TEXT, 
	source_ssh_sessions_file TEXT, 
	scenario TEXT, 
	label TEXT, 
	notes TEXT, 
	duration_ms INTEGER, quality TEXT, failure_reason TEXT, 
	PRIMARY KEY (run_id)
);
CREATE TABLE attack_run_metadata (
	run_id INTEGER NOT NULL, 
	attack_family TEXT NOT NULL, 
	attack_technique TEXT NOT NULL, 
	scenario TEXT NOT NULL, 
	tool TEXT, 
	tool_version TEXT, 
	target_host TEXT, 
	target_port INTEGER, 
	intensity TEXT, 
	parameters TEXT, 
	attack_start_ts TEXT, 
	attack_end_ts TEXT, 
	expected_behavior TEXT, 
	tool_version_check TEXT, 
	notes TEXT, 
	operator TEXT, 
	manifest_path TEXT, 
	created_at TEXT DEFAULT (datetime('now')) NOT NULL, run_uuid TEXT, manifest_hash TEXT, allow_nonzero_exit INTEGER DEFAULT '0' NOT NULL, 
	PRIMARY KEY (run_id), 
	FOREIGN KEY(run_id) REFERENCES observation_runs (run_id) ON DELETE CASCADE
);
CREATE INDEX idx_attack_run_metadata_family ON attack_run_metadata (attack_family);
CREATE INDEX idx_attack_run_metadata_technique ON attack_run_metadata (attack_technique);
CREATE TABLE correlated_events (
	id INTEGER NOT NULL, 
	run_id INTEGER NOT NULL, 
	timestamp TEXT NOT NULL, 
	src_ip TEXT, 
	dst_ip TEXT, 
	src_port INTEGER, 
	dst_port INTEGER, 
	transport TEXT, 
	direction TEXT, 
	process_pid INTEGER, 
	process_name TEXT, 
	dns_matched INTEGER NOT NULL, 
	dns_method TEXT, 
	dns_time_delta_ms INTEGER, 
	dns_response_latency_ms FLOAT, 
	tls_matched INTEGER NOT NULL, 
	tls_method TEXT, 
	tls_time_delta_ms INTEGER, 
	ssh_matched INTEGER NOT NULL, 
	ssh_method TEXT, 
	ssh_time_delta_ms INTEGER, 
	tcp_flow_matched INTEGER NOT NULL, 
	tcp_flow_method TEXT, 
	tcp_flow_time_delta_ms INTEGER, 
	http_matched INTEGER NOT NULL, 
	http_method TEXT, 
	http_time_delta_ms INTEGER, 
	process_context_matched INTEGER NOT NULL, 
	process_context_method TEXT, 
	file_activity_count INTEGER NOT NULL, 
	file_activity_method TEXT, 
	privilege_activity_count INTEGER NOT NULL, 
	privilege_activity_method TEXT, 
	raw_json TEXT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(run_id) REFERENCES observation_runs (run_id) ON DELETE CASCADE
);
CREATE INDEX idx_correlated_events_dst_ip ON correlated_events (dst_ip);
CREATE INDEX idx_correlated_events_process_pid ON correlated_events (process_pid);
CREATE INDEX idx_correlated_events_run_id ON correlated_events (run_id);
CREATE INDEX idx_correlated_events_run_timestamp ON correlated_events (run_id, timestamp);
CREATE INDEX idx_correlated_events_timestamp ON correlated_events (timestamp);
CREATE TABLE dns_events_raw (
	id INTEGER NOT NULL, 
	run_id INTEGER NOT NULL, 
	dedup_key TEXT NOT NULL, 
	timestamp TEXT, 
	event_type TEXT, 
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
	PRIMARY KEY (id), 
	FOREIGN KEY(run_id) REFERENCES observation_runs (run_id) ON DELETE CASCADE, 
	CONSTRAINT uq_dns_events_raw_run_dedup UNIQUE (run_id, dedup_key)
);
CREATE INDEX idx_dns_events_raw_query_name ON dns_events_raw (query_name);
CREATE INDEX idx_dns_events_raw_run_id ON dns_events_raw (run_id);
CREATE TABLE feature_windows (
	id INTEGER NOT NULL, 
	run_id INTEGER NOT NULL, 
	window_start_ts TEXT NOT NULL, 
	window_end_ts TEXT NOT NULL, 
	entity_type TEXT NOT NULL, 
	entity_id TEXT NOT NULL, 
	label INTEGER, 
	scenario TEXT, 
	attack_family TEXT, 
	attack_technique TEXT, 
	feature_version TEXT NOT NULL, 
	aggregation_version TEXT NOT NULL, 
	event_count INTEGER NOT NULL, 
	tcp_connect_count INTEGER NOT NULL, 
	tcp_close_count INTEGER NOT NULL, 
	dns_query_count INTEGER NOT NULL, 
	tls_connection_count INTEGER NOT NULL, 
	http_request_count INTEGER NOT NULL, 
	ssh_attempt_count INTEGER NOT NULL, 
	unique_dst_ip_count INTEGER NOT NULL, 
	unique_dst_port_count INTEGER NOT NULL, 
	unique_src_port_count INTEGER NOT NULL, 
	external_dst_ip_count INTEGER NOT NULL, 
	private_dst_ip_count INTEGER NOT NULL, 
	total_bytes_in INTEGER NOT NULL, 
	total_bytes_out INTEGER NOT NULL, 
	total_packets_in INTEGER NOT NULL, 
	total_packets_out INTEGER NOT NULL, 
	mean_flow_duration_sec FLOAT, 
	max_flow_duration_sec FLOAT, 
	failed_connection_count INTEGER NOT NULL, 
	failed_connection_ratio FLOAT, 
	connections_per_sec FLOAT, 
	bytes_per_sec_in FLOAT, 
	bytes_per_sec_out FLOAT, 
	packets_per_sec_in FLOAT, 
	packets_per_sec_out FLOAT, 
	interarrival_mean_ms FLOAT, 
	interarrival_std_ms FLOAT, 
	interarrival_p95_ms FLOAT, 
	dst_port_entropy FLOAT, 
	dst_ip_entropy FLOAT, 
	well_known_port_ratio FLOAT, 
	high_port_ratio FLOAT, 
	external_destination_ratio FLOAT, 
	unique_domain_count INTEGER NOT NULL, 
	nxdomain_count INTEGER NOT NULL, 
	nxdomain_ratio FLOAT, 
	mean_domain_length FLOAT, 
	max_domain_length INTEGER, 
	subdomain_depth_mean FLOAT, 
	unique_resolved_ip_count INTEGER NOT NULL, 
	dns_response_latency_mean_ms FLOAT, 
	dns_response_latency_p95_ms FLOAT, 
	mean_label_length FLOAT, 
	max_label_length INTEGER, 
	domain_label_entropy_mean FLOAT, 
	base32_like_ratio FLOAT, 
	base64_like_ratio FLOAT, 
	hex_like_ratio FLOAT, 
	unique_sni_count INTEGER NOT NULL, 
	missing_sni_count INTEGER NOT NULL, 
	missing_sni_ratio FLOAT, 
	unique_ja4_count INTEGER NOT NULL, 
	ja4_entropy FLOAT, 
	rare_ja4_ratio FLOAT, 
	tls_version_distribution TEXT, 
	most_common_ja4 TEXT, 
	most_common_ja4_count INTEGER, 
	http_unique_host_count INTEGER NOT NULL, 
	http_methods_distribution TEXT, 
	http_status_2xx_ratio FLOAT, 
	http_status_4xx_ratio FLOAT, 
	http_status_5xx_ratio FLOAT, 
	mean_path_length FLOAT, 
	mean_content_length FLOAT, 
	process_exec_count INTEGER NOT NULL, 
	unique_binary_count INTEGER NOT NULL, 
	shell_spawn_count INTEGER NOT NULL, 
	interpreter_spawn_count INTEGER NOT NULL, 
	process_tree_depth_max INTEGER, 
	sensitive_file_event_count INTEGER NOT NULL, 
	privilege_event_count INTEGER NOT NULL, 
	sudo_exec_count INTEGER NOT NULL, 
	pkexec_count INTEGER NOT NULL, 
	su_exec_count INTEGER NOT NULL, 
	capability_event_count INTEGER NOT NULL, 
	seconds_since_last_privilege_event FLOAT, 
	seconds_since_last_sensitive_file_access FLOAT, 
	network_events_after_privilege_event INTEGER, 
	network_events_after_sensitive_file_access INTEGER, 
	ssh_success_count INTEGER NOT NULL, 
	ssh_failure_count INTEGER NOT NULL, 
	ssh_failure_ratio FLOAT, 
	ssh_session_count INTEGER NOT NULL, 
	mean_ssh_session_duration_sec FLOAT, 
	contributing_event_ids TEXT, 
	total_flow_count INTEGER NOT NULL, 
	created_at TEXT DEFAULT (datetime('now')) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(run_id) REFERENCES observation_runs (run_id) ON DELETE CASCADE
);
CREATE INDEX idx_feature_windows_entity ON feature_windows (entity_type, entity_id);
CREATE INDEX idx_feature_windows_label ON feature_windows (label);
CREATE INDEX idx_feature_windows_run_id ON feature_windows (run_id);
CREATE INDEX idx_feature_windows_timestamp ON feature_windows (window_start_ts, window_end_ts);
CREATE TABLE ssh_sessions (
	id INTEGER NOT NULL, 
	run_id INTEGER NOT NULL, 
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
	session_duration_seconds FLOAT, 
	disconnected_ts TEXT, 
	tcp_connect_matched INTEGER NOT NULL, 
	tcp_connect_dst_ip TEXT, 
	tcp_connect_time_delta_ms INTEGER, 
	tcp_close_matched INTEGER NOT NULL, 
	tcp_close_timestamp TEXT, 
	connection_duration_seconds FLOAT, 
	execve_matched INTEGER NOT NULL, 
	execve_binary TEXT, 
	execve_timestamp TEXT, 
	raw_json TEXT NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(run_id) REFERENCES observation_runs (run_id) ON DELETE CASCADE
);
CREATE INDEX idx_ssh_sessions_run_id ON ssh_sessions (run_id);
CREATE INDEX idx_ssh_sessions_session_key ON ssh_sessions (session_key);
CREATE TABLE tcp_flows_raw (
	id INTEGER NOT NULL, 
	run_id INTEGER NOT NULL, 
	dedup_key TEXT NOT NULL, 
	src_ip TEXT, 
	src_port INTEGER, 
	dst_ip TEXT, 
	dst_port INTEGER, 
	transport TEXT, 
	direction TEXT, 
	start_ts TEXT, 
	end_ts TEXT, 
	duration_ms INTEGER, 
	handshake_completed INTEGER, 
	handshake_rtt_ms FLOAT, 
	termination_reason TEXT, 
	packets_out INTEGER, 
	packets_in INTEGER, 
	bytes_out INTEGER, 
	bytes_in INTEGER, 
	retransmissions INTEGER, 
	raw_json TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(run_id) REFERENCES observation_runs (run_id) ON DELETE CASCADE, 
	CONSTRAINT uq_tcp_flows_raw_run_dedup UNIQUE (run_id, dedup_key)
);
CREATE INDEX idx_tcp_flows_raw_run_id ON tcp_flows_raw (run_id);
CREATE TABLE dns_observations (
	id INTEGER NOT NULL, 
	correlated_event_id INTEGER NOT NULL, 
	timestamp TEXT, 
	query_name TEXT, 
	query_type INTEGER, 
	transaction_id INTEGER, 
	rcode INTEGER, 
	answer_count INTEGER, 
	resolved_ip TEXT, 
	ttl INTEGER, 
	response_latency_ms FLOAT, 
	raw_json TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(correlated_event_id) REFERENCES correlated_events (id) ON DELETE CASCADE
);
CREATE INDEX idx_dns_observations_correlated_event_id ON dns_observations (correlated_event_id);
CREATE INDEX idx_dns_observations_query_name ON dns_observations (query_name);
CREATE INDEX idx_dns_observations_resolved_ip ON dns_observations (resolved_ip);
CREATE TABLE file_activity_events (
	id INTEGER NOT NULL, 
	correlated_event_id INTEGER NOT NULL, 
	timestamp TEXT, 
	path TEXT, 
	operations TEXT, 
	source_event_key TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(correlated_event_id) REFERENCES correlated_events (id) ON DELETE CASCADE
);
CREATE INDEX idx_file_activity_correlated_event_id ON file_activity_events (correlated_event_id);
CREATE INDEX idx_file_activity_path ON file_activity_events (path);
CREATE TABLE http_observations (
	id INTEGER NOT NULL, 
	correlated_event_id INTEGER NOT NULL, 
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
	raw_json TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(correlated_event_id) REFERENCES correlated_events (id) ON DELETE CASCADE
);
CREATE INDEX idx_http_observations_correlated_event_id ON http_observations (correlated_event_id);
CREATE INDEX idx_http_observations_host ON http_observations (host);
CREATE INDEX idx_http_observations_status_code ON http_observations (status_code);
CREATE TABLE privilege_activity_events (
	id INTEGER NOT NULL, 
	correlated_event_id INTEGER NOT NULL, 
	timestamp TEXT, 
	event_type TEXT, 
	detail TEXT, 
	source_event_key TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(correlated_event_id) REFERENCES correlated_events (id) ON DELETE CASCADE
);
CREATE INDEX idx_privilege_activity_correlated_event_id ON privilege_activity_events (correlated_event_id);
CREATE TABLE process_observations (
	id INTEGER NOT NULL, 
	correlated_event_id INTEGER NOT NULL, 
	timestamp TEXT, 
	exec_id TEXT, 
	parent_exec_id TEXT, 
	parent_binary TEXT, 
	arguments TEXT, 
	uid INTEGER, 
	cwd TEXT, 
	raw_json TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(correlated_event_id) REFERENCES correlated_events (id) ON DELETE CASCADE
);
CREATE INDEX idx_process_observations_correlated_event_id ON process_observations (correlated_event_id);
CREATE INDEX idx_process_observations_exec_id ON process_observations (exec_id);
CREATE TABLE tcp_flow_observations (
	id INTEGER NOT NULL, 
	correlated_event_id INTEGER NOT NULL, 
	start_ts TEXT, 
	end_ts TEXT, 
	duration_seconds FLOAT, 
	duration_ms INTEGER, 
	handshake_completed INTEGER, 
	handshake_rtt_ms FLOAT, 
	termination_reason TEXT, 
	packets_out INTEGER, 
	packets_in INTEGER, 
	bytes_out INTEGER, 
	bytes_in INTEGER, 
	retransmissions INTEGER, 
	raw_json TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(correlated_event_id) REFERENCES correlated_events (id) ON DELETE CASCADE
);
CREATE INDEX idx_tcp_flow_observations_correlated_event_id ON tcp_flow_observations (correlated_event_id);
CREATE TABLE tls_observations (
	id INTEGER NOT NULL, 
	correlated_event_id INTEGER NOT NULL, 
	timestamp TEXT, 
	sni TEXT, 
	ja4 TEXT, 
	tls_version TEXT, 
	raw_json TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(correlated_event_id) REFERENCES correlated_events (id) ON DELETE CASCADE
);
CREATE INDEX idx_tls_observations_correlated_event_id ON tls_observations (correlated_event_id);
CREATE INDEX idx_tls_observations_ja4 ON tls_observations (ja4);
CREATE INDEX idx_tls_observations_sni ON tls_observations (sni);
CREATE UNIQUE INDEX idx_attack_run_metadata_run_uuid ON attack_run_metadata (run_uuid);
