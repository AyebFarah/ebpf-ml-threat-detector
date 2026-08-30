from observation.pipeline.normalizer import normalize_sensitive_file_access

SAMPLE = {
    "process_kprobe": {
        "policy_name": "sensitive-file-access",
        "process": {"pid": 4821, "binary": "/usr/bin/cat"},
        "args": [
            {"file_arg": {"path": "/etc/shadow"}},
            {"label": "mask", "int_arg": 4},  # MAY_READ
        ],
    },
    "time": "2026-08-15T10:20:00.000000000Z",
}

# Verifies that a sensitive file-access event is correctly normalized by
# preserving the accessed file, the process responsible for the access, and
# the type of operation. The raw kernel permission mask is translated into
# a semantic operation such as "read", making the behavior easier to analyze.

def test_normalize_file_access_classifies_read():
    event = normalize_sensitive_file_access(SAMPLE)
    assert event["source"] == "file"
    assert event["extra"]["path"] == "/etc/shadow"
    assert event["extra"]["operations"] == ["read"]
    assert event["process"]["name"] == "/usr/bin/cat"