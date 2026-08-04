import json
import os

BY_POLICY_DIR = os.path.join(os.path.dirname(__file__), "..", "samples", "event_logs_by_policy")

POLICY_FILE_MAP = {
    "tcp-connect": "tcp-connect.jsonl",
    "dns-queries": "dns-queries.jsonl",
    "dot-queries": "dot-queries.jsonl",
    "ssh-sessions": "ssh-sessions.jsonl",
    "listening-ports": "listening-ports.jsonl",
}

def dispatch_raw_event(raw: dict):
    os.makedirs(BY_POLICY_DIR, exist_ok=True)

    kprobe = raw.get("process_kprobe")

    if kprobe is None:
        _append(os.path.join(BY_POLICY_DIR, "process-lifecycle.jsonl"), raw)
        return

    policy_name = kprobe.get("policy_name")
    filename = POLICY_FILE_MAP.get(policy_name)

    if filename is None:
        _append(os.path.join(BY_POLICY_DIR, "_unmapped.jsonl"), raw)
        return

    _append(os.path.join(BY_POLICY_DIR, filename), raw)


def _append(path: str, obj: dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")
