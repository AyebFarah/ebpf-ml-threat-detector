import json
import sys
from observation import paths


def dispatch_raw_event(raw: dict):
    paths.EVENT_LOGS_BY_POLICY_DIR.mkdir(parents=True, exist_ok=True)

    if "process_exec" in raw:
        _append(paths.PROCESS_EXEC_POLICY_FILE, raw)
        return

    if "process_exit" in raw:
        _append(paths.PROCESS_EXIT_POLICY_FILE, raw)
        return

    kprobe = raw.get("process_kprobe")
    if kprobe is None:
        return

    policy_name = kprobe.get("policy_name")
    target_file = paths.POLICY_FILE_MAP.get(policy_name)
    if target_file is None:
        return

    _append(target_file, raw)


def _append(path, obj: dict):
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
                print(f"[dispatcher] skipping malformed line: {line[:100]}", file=sys.stderr)
                continue
            dispatch_raw_event(raw)
    except KeyboardInterrupt:
        print("\n[dispatcher] stopped.")

if __name__ == "__main__":
    run_stdin_loop()