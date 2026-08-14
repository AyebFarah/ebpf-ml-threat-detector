import json
import os
import sys

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


def run_stdin_loop():
    try:
        for line in sys.stdin:
            line = line.strip()

            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"[dispatcher] skipping malformed line: {line[:100]}",
                    file=sys.stderr,
                )
                continue

            dispatch_raw_event(raw)

    except KeyboardInterrupt:
        print("\n[dispatcher] stopped.")

if __name__ == "__main__":
    run_stdin_loop()
