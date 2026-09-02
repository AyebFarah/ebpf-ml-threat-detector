from ...pipeline.normalizer import normalize_sudo_exec, normalize_capability_change

SAMPLE_SUDO = {
    "process_kprobe": {
        "policy_name": "sudo-exec",
        "process": {"pid": 9001, "binary": "/usr/bin/sudo", "uid": 1000,
                    "arguments": "apt update"},
        "parent": {"pid": 8990, "binary": "/bin/bash"},
    },
    "time": "2026-08-15T09:00:00.000000000Z",
}

SAMPLE_CAP = {
    "process_kprobe": {
        "policy_name": "capability-change",
        "process": {"pid": 9001, "binary": "/usr/bin/sudo", "uid": 0},
        "args": [{"label": "cap", "int_arg": 21}],
    },
    "time": "2026-08-15T09:00:00.100000000Z",
}


def test_normalize_sudo_exec_captures_lineage():
    event = normalize_sudo_exec(SAMPLE_SUDO)
    assert event["source"] == "privilege"
    assert event["event_type"] == "sudo_exec"
    assert event["extra"]["parent_binary"] == "/bin/bash"
    assert event["extra"]["arguments"] == "apt update"


def test_normalize_capability_change_extracts_cap_number():
    event = normalize_capability_change(SAMPLE_CAP)
    assert event["event_type"] == "capability_use"
    assert event["extra"]["capability"] == 21