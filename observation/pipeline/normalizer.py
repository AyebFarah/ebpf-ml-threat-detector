import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SAMPLES_DIR = BASE_DIR / "samples"
OUTPUT_DIR = SAMPLES_DIR / "unified_events"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = OUTPUT_DIR / "unified_events.jsonl"

COMMON_FIELDS = {
    "timestamp", "event_type", "src_ip", "dst_ip",
    "src_port", "dst_port", "transport", "direction",
}

PROTOCOL_NUMBER_MAP = {
    6: "tcp",
    17: "udp",
}

PROTOCOL_NAME_MAP = {
    "ipproto_tcp": "tcp",
    "ipproto_udp": "udp",
    "tcp": "tcp",
    "udp": "udp",
}

# Matches a fractional-seconds group of more than 6 digits, e.g. the ".468189729" in "2026-08-11T15:48:22.468189729Z".
_OVERLONG_FRACTION_RE = re.compile(r"(\.\d{6})\d+")

# Maps architecture-specific kprobe function names to a unified event_type.
FUNCTION_NAME_MAP = {
    "__x64_sys_execve": "sys_execve",
    "__ia32_sys_execve": "sys_execve",
}


def normalize_function_name(function_name):
    return FUNCTION_NAME_MAP.get(function_name, function_name)


def reset_output_file() -> None:
    OUTPUT_FILE.write_text("", encoding="utf-8")


def write_event(event: dict) -> None:
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def normalize_transport(value):
    if value is None:
        return None
    if isinstance(value, str):
        if value.isdigit():
            return PROTOCOL_NUMBER_MAP.get(int(value))
        return PROTOCOL_NAME_MAP.get(value.lower())
    try:
        return PROTOCOL_NUMBER_MAP.get(int(value))
    except (TypeError, ValueError):
        return None


def normalize_timestamp(ts):
    """
    Truncate any fractional-second precision beyond microseconds down
    to 6 digits, so every timestamp in unified_events.jsonl is safe to
    parse with datetime.fromisoformat() on any Python version.
    """
    if not isinstance(ts, str):
        return ts
    return _OVERLONG_FRACTION_RE.sub(r"\1", ts)


def _split_common_and_extra(raw: dict):
    common = {k: raw.get(k) for k in COMMON_FIELDS}
    common["transport"] = normalize_transport(common.get("transport"))
    common["timestamp"] = normalize_timestamp(common.get("timestamp"))
    extra = {k: v for k, v in raw.items() if k not in COMMON_FIELDS}
    return common, extra


def normalize_dns(raw: dict) -> dict:
    common, extra = _split_common_and_extra(raw)
    return {**common, "source": "dns", "process": None, "extra": extra}


def normalize_tls(raw: dict) -> dict:
    common, extra = _split_common_and_extra(raw)
    return {**common, "source": "tls", "process": None, "extra": extra}


def normalize_ssh(raw: dict) -> dict:
    """
    ssh-collector.py already emits flat, already-typed events, so this
    just splits common/extra like the other host-side sources. `extra`
    ends up carrying username, auth_method, result, invalid_user,
    session_duration_seconds, pid, and session_key.
    """
    common, extra = _split_common_and_extra(raw)
    return {
        **common,
        "source": "ssh",
        "process": {"pid": raw.get("pid")} if raw.get("pid") is not None else None,
        "extra": extra,
    }


def normalize_tetragon(raw: dict) -> dict:
    kprobe = raw.get("process_kprobe", {})
    process = kprobe.get("process", {})
    args = kprobe.get("args", [])

    src_ip = dst_ip = src_port = dst_port = transport = None
    for arg in args:
        sock = arg.get("sock_arg")
        if sock:
            src_ip = sock.get("saddr")
            dst_ip = sock.get("daddr")
            src_port = sock.get("sport")
            dst_port = sock.get("dport")
            transport = sock.get("protocol")

    function_name = kprobe.get("function_name")
    unified_function_name = normalize_function_name(function_name)
    direction = "outbound" if function_name == "tcp_connect" else None

    return {
        "timestamp": normalize_timestamp(raw.get("time")),
        "event_type": unified_function_name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "transport": normalize_transport(transport),
        "direction": direction,
        "source": "tetragon",
        "process": {
            "pid": process.get("pid"),
            "name": process.get("binary"),
        } if process else None,
        "extra": {
            "policy_name": kprobe.get("policy_name"),
            "function_name": function_name,
            "args": args,
        },
    }


def normalize_ssh_sessions_policy(raw: dict):
    """
    ssh-sessions.yaml captures tcp_connect/tcp_close on port 22 (which
    duplicate what tcp-connections.yaml already gives us in
    tcp-connect.jsonl, since both fire on the same kernel calls) AND
    sys_execve for sshd/ssh/ssh-agent (which nothing else captures).
    We only want the execve half here — the connect/close duplicates
    are dropped by returning None for them.
    """
    kprobe = raw.get("process_kprobe", {})
    if normalize_function_name(kprobe.get("function_name")) != "sys_execve":
        return None
    return normalize_tetragon(raw)

def normalize_tcp(raw: dict) -> dict:
    common, extra = _split_common_and_extra(raw)
    return {**common, "source": "tcp", "process": None, "extra": extra}


NORMALIZERS = {
    "dns": normalize_dns,
    "tls": normalize_tls,
    "tcp": normalize_tcp,
    "ssh": normalize_ssh,
    "tetragon": normalize_tetragon,
    "ssh_exec": normalize_ssh_sessions_policy,
}


def normalize_file(input_path: Path, source: str) -> int:
    normalizer_fn = NORMALIZERS[source]
    count = 0
    with input_path.open(encoding="utf-8") as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            event = normalizer_fn(raw)
            if event is None:
                continue
            write_event(event)
            count += 1
    return count

def main():
    reset_output_file()
    sources = [
        (SAMPLES_DIR / "collectors_events" / "dns_events.jsonl", "dns"),
        (SAMPLES_DIR / "collectors_events" / "tls_events.jsonl", "tls"),
        (SAMPLES_DIR / "collectors_events" / "ssh_events.jsonl", "ssh"),
        (SAMPLES_DIR / "event_logs_by_policy" / "tcp-connect.jsonl", "tetragon"),
        (SAMPLES_DIR / "event_logs_by_policy" / "ssh-sessions.jsonl", "ssh_exec"),
        (SAMPLES_DIR / "collectors_events" / "tcp_events.jsonl", "tcp"),

    ]

    counts = {"dns": 0, "tls": 0, "ssh": 0, "tetragon": 0, "ssh_exec": 0, "tcp":0}

    for path, source in sources:
        if not path.exists():
            print(f"[normalizer] skip (missing): {path}")
            continue
        counts[source] += normalize_file(path, source)

    total = sum(counts.values())
    print(f"DNS      : {counts['dns']} events")
    print(f"TLS      : {counts['tls']} events")
    print(f"SSH      : {counts['ssh']} events")
    print(f"TCP      : {counts['tcp']} events")
    print(f"Tetragon : {counts['tetragon']} events")
    print(f"SSH exec : {counts['ssh_exec']} events")
    print(f"Total    : {total}")
    print(f"-> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
