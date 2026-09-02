import json
from ...pipeline.dispatcher import dispatch_raw_event
from ...pipeline.normalizer import normalize_process_exec, normalize_process_exit
from ... import paths

SAMPLE_EXEC = {
    "process_exec": {
        "process": {
            "exec_id": "node1:123:45678",
            "pid": 45678,
            "uid": 1000,
            "cwd": "/home/pharah",
            "binary": "/usr/bin/python3",
            "arguments": "update.py --sync",
            "start_time": "2026-08-15T10:15:23.123456789Z",
            "parent_exec_id": "node1:123:45677",
        },
        "parent": {"exec_id": "node1:123:45677", "pid": 45677, "binary": "/usr/sbin/sshd"},
    },
    "time": "2026-08-19T10:15:23.123456789Z",
}

SAMPLE_EXIT = {
    "process_exit": {
        "process": {"exec_id": "node1:123:45678", "pid": 45678, "binary": "/usr/bin/python3"},
        "signal": None,
        "status": 0,
    },
    "time": "2026-08-15T10:15:30.000000000Z",
}


# Verifies that a raw Tetragon process_exec event is correctly identified and routed by the dispatcher to the dedicated process-exec.jsonl file.

def test_dispatch_routes_process_exec_to_own_file(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "EVENT_LOGS_BY_POLICY_DIR", tmp_path)
    monkeypatch.setattr(paths, "PROCESS_EXEC_POLICY_FILE", tmp_path / "process-exec.jsonl")
    dispatch_raw_event(SAMPLE_EXEC)
    out = (tmp_path / "process-exec.jsonl").read_text().strip()
    assert json.loads(out)["process_exec"]["process"]["pid"] == 45678


# Verifies that the process_exec normalizer preserves the information needed
# to identify the process and reconstruct its parent-child lineage.
# In particular, exec_id and parent_exec_id allow us to relate a process to
# its parent, while parent_binary identifies the program that created it.

def test_normalize_process_exec_extracts_exec_id_and_lineage():
    event = normalize_process_exec(SAMPLE_EXEC)
    assert event["source"] == "process"
    assert event["event_type"] == "process_exec"
    assert event["process"]["pid"] == 45678
    assert event["extra"]["exec_id"] == "node1:123:45678"
    assert event["extra"]["parent_exec_id"] == "node1:123:45677"
    assert event["extra"]["parent_binary"] == "/usr/sbin/sshd"

# Verifies that process_exit events retain the identity and termination result
# of the process that exited. The exec_id links the termination event back to
# the corresponding process_exec event, while the exit status describes how
# the process terminated.

def test_normalize_process_exit_carries_exit_status():
    event = normalize_process_exit(SAMPLE_EXIT)
    assert event["event_type"] == "process_exit"
    assert event["extra"]["exec_id"] == "node1:123:45678"
    assert event["extra"]["status"] == 0