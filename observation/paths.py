from pathlib import Path

OBSERVATION_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = OBSERVATION_DIR / "samples"

COLLECTORS_EVENTS_DIR = SAMPLES_DIR / "collectors_events"
EVENT_LOGS_BY_POLICY_DIR = SAMPLES_DIR / "event_logs_by_policy"
UNIFIED_EVENTS_DIR = SAMPLES_DIR / "unified_events"

# Collector outputs
DNS_EVENTS_FILE = COLLECTORS_EVENTS_DIR / "dns_events.jsonl"
TLS_EVENTS_FILE = COLLECTORS_EVENTS_DIR / "tls_events.jsonl"
SSH_EVENTS_FILE = COLLECTORS_EVENTS_DIR / "ssh_events.jsonl"
TCP_EVENTS_FILE = COLLECTORS_EVENTS_DIR / "tcp_events.jsonl"
HTTP_EVENTS_FILE = COLLECTORS_EVENTS_DIR / "http_events.jsonl"


# Tetragon dispatcher outputs — one file per policy, plus two catch-alls.
# Defined once here so dispatcher.py, normalizer.py, and bootstrap.py all
# reference the same filenames instead of each keeping their own copy.
TCP_CONNECT_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "tcp-connect.jsonl"
DNS_QUERIES_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "dns-queries.jsonl"
DOT_QUERIES_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "dot-queries.jsonl"
SSH_SESSIONS_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "ssh-sessions.jsonl"
PROCESS_EXEC_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "process-exec.jsonl"
PROCESS_EXIT_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "process-exit.jsonl"
LISTENING_PORTS_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "listening-ports.jsonl"
SENSITIVE_FILE_ACCESS_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "sensitive-file-access.jsonl"
SUDO_EXEC_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "sudo-exec.jsonl"
CAPABILITY_CHANGE_POLICY_FILE = EVENT_LOGS_BY_POLICY_DIR / "capability-change.jsonl"

# Maps a Tetragon policy_name (from policies/*.yaml) to the file dispatcher.py routes its events into.
POLICY_FILE_MAP = {
    "tcp-connect": TCP_CONNECT_POLICY_FILE,
    "dns-queries": DNS_QUERIES_POLICY_FILE,
    "dot-queries": DOT_QUERIES_POLICY_FILE,
    "ssh-sessions": SSH_SESSIONS_POLICY_FILE,
    "listening-ports": LISTENING_PORTS_POLICY_FILE,
    "sensitive-file-access": SENSITIVE_FILE_ACCESS_POLICY_FILE,
    "sudo-exec": SUDO_EXEC_POLICY_FILE,
    "capability-change": CAPABILITY_CHANGE_POLICY_FILE,

}

# Pipeline outputs
UNIFIED_EVENTS_FILE = UNIFIED_EVENTS_DIR / "unified_events.jsonl"
CORRELATED_EVENTS_FILE = UNIFIED_EVENTS_DIR / "correlated_events.jsonl"
SSH_SESSIONS_FILE = UNIFIED_EVENTS_DIR / "ssh_sessions.jsonl"

REQUIRED_DIRS = (
    COLLECTORS_EVENTS_DIR,
    EVENT_LOGS_BY_POLICY_DIR,
    UNIFIED_EVENTS_DIR,
)

# Database
DATABASE_DIR = OBSERVATION_DIR / "database"
DATABASE_FILE = DATABASE_DIR / "observations.db"
MIGRATIONS_DIR = DATABASE_DIR / "migrations"