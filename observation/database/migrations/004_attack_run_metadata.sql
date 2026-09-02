CREATE TABLE IF NOT EXISTS attack_run_metadata (
    run_id INTEGER PRIMARY KEY REFERENCES observation_runs(run_id) ON DELETE CASCADE,
    attack_family TEXT NOT NULL,
    attack_technique TEXT NOT NULL,
    scenario TEXT NOT NULL,
    tool TEXT,
    tool_version TEXT,
    target_host TEXT,
    target_port INTEGER,
    intensity TEXT,              -- 'low' | 'medium' | 'high', NULL if not applicable
    parameters TEXT,             -- JSON blob of the script's actual parameters
    attack_start_ts TEXT,
    attack_end_ts TEXT,
    expected_behavior TEXT,
    tool_version_check TEXT,     -- raw output of `tool --version`, for audit
    notes TEXT,
    operator TEXT,
    manifest_path TEXT,          -- path to the JSON manifest file
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

CREATE INDEX IF NOT EXISTS idx_attack_run_metadata_family ON attack_run_metadata(attack_family);
CREATE INDEX IF NOT EXISTS idx_attack_run_metadata_technique ON attack_run_metadata(attack_technique);