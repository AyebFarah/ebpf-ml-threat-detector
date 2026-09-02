import json
import re
from .. import paths
from datetime import datetime


SAMPLES_DIR = paths.SAMPLES_DIR
OUTPUT_FILE = paths.UNIFIED_EVENTS_FILE

CAPABILITY_AGGREGATION_WINDOW_SECONDS = 10

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

MAY_READ = 0x4
MAY_WRITE = 0x2

def normalize_function_name(function_name):
    return FUNCTION_NAME_MAP.get(function_name, function_name)


def reset_output_file() -> None:
    OUTPUT_FILE.write_text("", encoding="utf-8")


def write_event(event: dict) -> None:
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def _classify_file_mask(mask):
    if mask is None:
        return None
    ops = []
    if mask & MAY_READ:
        ops.append("read")
    if mask & MAY_WRITE:
        ops.append("write")
    return ops or ["other"]

def normalize_ip(ip):
    """
    Tetragon reports IPv4 traffic on dual-stack AF_INET6 sockets as
    IPv4-mapped IPv6 addresses (e.g. '::ffff:192.168.1.24'). Scapy-based
    collectors (tcp_collector, tls_collector, dns_collector) read the wire
    directly and never produce this prefix. Stripping it here keeps every
    source's IPs in the same plain-IPv4 form so 5-tuple correlation keys
    actually line up across sources.
    """
    if isinstance(ip, str) and ip.startswith("::ffff:"):
        return ip[len("::ffff:"):]
    return ip

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

def _split_common_and_extra(raw: dict):
    common = {k: raw.get(k) for k in COMMON_FIELDS}
    common["transport"] = normalize_transport(common.get("transport"))
    common["timestamp"] = normalize_timestamp(common.get("timestamp"))
    extra = {k: v for k, v in raw.items() if k not in COMMON_FIELDS}
    return common, extra


def normalize_timestamp(ts):
    """
    Truncate any fractional-second precision beyond microseconds down
    to 6 digits, so every timestamp in unified_events.jsonl is safe to
    parse with datetime.fromisoformat() on any Python version.
    """
    if not isinstance(ts, str):
        return ts
    return _OVERLONG_FRACTION_RE.sub(r"\1", ts)


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
            src_ip = normalize_ip(sock.get("saddr"))
            dst_ip = normalize_ip(sock.get("daddr"))
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

def normalize_http(raw: dict) -> dict:
    common, extra = _split_common_and_extra(raw)
    return {**common, "source": "http", "process": None, "extra": extra}

def index_dns_queries(events: list) -> dict:
    """
    Key: (transaction_id, client_ip, resolver_ip) exactly as seen on a
    query -- src_ip is the client, dst_ip is the resolver. Responses
    are matched by looking up the reversed pair, since a response
    travels resolver -> client.
    """
    index = {}
    for e in events:
        if e["event_type"] != "dns_query":
            continue
        transaction_id = e.get("extra", {}).get("transaction_id")
        key = (transaction_id, e.get("src_ip"), e.get("dst_ip"))
        index.setdefault(key, []).append(e)
    for key in index:
        index[key].sort(key=lambda e: parse_ts(e["timestamp"]))
    return index


def attach_dns_response_latency(events: list) -> list:
    """
    For every dns_response event, find the dns_query that shares its
    transaction_id and has the reversed client/resolver IP pair, then
    stamp extra.response_latency_ms with the round-trip time. Mutates
    and returns the same list -- events without a match get
    response_latency_ms: None rather than being dropped.
    """
    query_index = index_dns_queries(events)

    for e in events:
        if e["event_type"] != "dns_response":
            continue
        transaction_id = e.get("extra", {}).get("transaction_id")
        # response src_ip is the resolver, dst_ip is the client --
        # reverse of how the query indexed its own (src, dst).
        key = (transaction_id, e.get("dst_ip"), e.get("src_ip"))
        candidates = query_index.get(key, [])

        resp_ts = parse_ts(e["timestamp"])
        best = None
        for q in candidates:  # sorted ascending
            if parse_ts(q["timestamp"]) <= resp_ts:
                best = q
            else:
                break

        if best is not None:
            delta_ms = (resp_ts - parse_ts(best["timestamp"])).total_seconds() * 1000
            e["extra"]["response_latency_ms"] = round(delta_ms, 3)
        else:
            e["extra"]["response_latency_ms"] = None

    return events

def normalize_dns_file(input_path) -> int:
    if not input_path.exists():
        return 0
    normalized = []
    with input_path.open(encoding="utf-8") as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            normalized.append(normalize_dns(json.loads(line)))

    normalized = attach_dns_response_latency(normalized)
    for event in normalized:
        write_event(event)
    return len(normalized)


def normalize_process_exec(raw: dict) -> dict:
    proc = raw.get("process_exec", {}).get("process", {})
    parent = raw.get("process_exec", {}).get("parent", {})
    return {
        "timestamp": normalize_timestamp(raw.get("time")),
        "event_type": "process_exec",
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "transport": None, "direction": None,
        "source": "process",
        "process": {
            "pid": proc.get("pid"),
            "name": proc.get("binary"),
        },
        "extra": {
            "exec_id": proc.get("exec_id"),
            "parent_exec_id": proc.get("parent_exec_id"),
            "parent_pid": parent.get("pid"),
            "parent_binary": parent.get("binary"),
            "uid": proc.get("uid"),
            "auid": proc.get("auid"),
            "cwd": proc.get("cwd"),
            "arguments": proc.get("arguments"),
            "start_time": proc.get("start_time"),
            "flags": proc.get("flags"),
        },
    }


def normalize_process_exit(raw: dict) -> dict:
    proc = raw.get("process_exit", {}).get("process", {})
    return {
        "timestamp": normalize_timestamp(raw.get("time")),
        "event_type": "process_exit",
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "transport": None, "direction": None,
        "source": "process",
        "process": {
            "pid": proc.get("pid"),
            "name": proc.get("binary"),
        },
        "extra": {
            "exec_id": proc.get("exec_id"),
            "signal": raw.get("process_exit", {}).get("signal"),
            "status": raw.get("process_exit", {}).get("status"),
        },
    }

def normalize_sensitive_file_access(raw: dict) -> dict:
    kprobe = raw.get("process_kprobe", {})
    process = kprobe.get("process", {})
    args = kprobe.get("args", [])

    path = None
    mask = None
    for arg in args:
        if "file_arg" in arg:
            path = arg["file_arg"].get("path")
        if arg.get("label") == "mask":
            mask = arg.get("int_arg")

    return {
        "timestamp": normalize_timestamp(raw.get("time")),
        "event_type": "file_access",
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "transport": None, "direction": None,
        "source": "file",
        "process": {
            "pid": process.get("pid"),
            "name": process.get("binary"),
        } if process else None,
        "extra": {
            "path": path,
            "operations": _classify_file_mask(mask),
            "policy_name": kprobe.get("policy_name"),
        },
    }

def normalize_sudo_exec(raw: dict) -> dict:
    kprobe = raw.get("process_kprobe", {})
    process = kprobe.get("process", {})
    parent = kprobe.get("parent", {})
    return {
        "timestamp": normalize_timestamp(raw.get("time")),
        "event_type": "sudo_exec",
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "transport": None, "direction": None,
        "source": "privilege",
        "process": {
            "pid": process.get("pid"),
            "name": process.get("binary"),
        } if process else None,
        "extra": {
            "arguments": process.get("arguments"),
            "uid": process.get("uid"),
            "parent_binary": parent.get("binary"),
            "parent_pid": parent.get("pid"),
            "policy_name": kprobe.get("policy_name"),
        },
    }


def _capability_agg_key(event: dict):
    pid = (event.get("process") or {}).get("pid")
    cap = event.get("extra", {}).get("capability")
    return (pid, cap)


def aggregate_capability_events(raw_events: list) -> list:
    """
    Collapse repeated cap_capable events for the same (pid, capability)
    within CAPABILITY_AGGREGATION_WINDOW_SECONDS into a single summarized
    event carrying a count, instead of emitting one row per kernel-side
    permission check. Mirrors tcp_collector.py's flow aggregation: many
    raw occurrences -> one meaningful record with count/duration.
    """
    raw_events = sorted(raw_events, key=lambda e: e["timestamp"])
    open_windows = {}
    aggregated = []

    for event in raw_events:
        key = _capability_agg_key(event)
        ts = parse_ts(event["timestamp"])
        window = open_windows.get(key)

        if window is not None:
            window_start = parse_ts(window["first_seen"])
            if (ts - window_start).total_seconds() <= CAPABILITY_AGGREGATION_WINDOW_SECONDS:
                window["count"] += 1
                window["last_seen"] = event["timestamp"]
                continue
            else:
                aggregated.append(window)

        open_windows[key] = {
            **event,
            "event_type": "capability_use",
            "extra": {**event["extra"], "count": 1,
                      "first_seen": event["timestamp"],
                      "last_seen": event["timestamp"]},
            "first_seen": event["timestamp"],
            "count": 1,
        }

    aggregated.extend(open_windows.values())
    return aggregated


def normalize_capability_change(raw: dict) -> dict:
    kprobe = raw.get("process_kprobe", {})
    process = kprobe.get("process", {})
    args = kprobe.get("args", [])

    cap = None
    for arg in args:
        if arg.get("label") == "cap":
            cap = arg.get("int_arg")

    return {
        "timestamp": normalize_timestamp(raw.get("time")),
        "event_type": "capability_use_raw",
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "transport": None, "direction": None,
        "source": "privilege",
        "process": {
            "pid": process.get("pid"),
            "name": process.get("binary"),
        } if process else None,
        "extra": {
            "capability": cap,
            "uid": process.get("uid"),
            "policy_name": kprobe.get("policy_name"),
        },
    }

def normalize_capability_file(input_path) -> int:
    if not input_path.exists():
        return 0
    raw_normalized = []
    with input_path.open(encoding="utf-8") as infile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            raw_normalized.append(normalize_capability_change(json.loads(line)))

    aggregated = aggregate_capability_events(raw_normalized)
    for event in aggregated:
        write_event(event)
    return len(aggregated)

def normalize_file(input_path: paths, source: str) -> int:
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

NORMALIZERS = {
    "dns": normalize_dns,
    "tls": normalize_tls,
    "tcp": normalize_tcp,
    "ssh": normalize_ssh,
    "tetragon": normalize_tetragon,
    "ssh_exec": normalize_ssh_sessions_policy,
    "process_exec": normalize_process_exec,
    "process_exit": normalize_process_exit,
    "file_access": normalize_sensitive_file_access,
    "sudo_exec": normalize_sudo_exec,
    "capability_change": normalize_capability_change,
    "http": normalize_http,
}

def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    reset_output_file()
    sources = [
        (paths.TLS_EVENTS_FILE, "tls"),
        (paths.SSH_EVENTS_FILE, "ssh"),
        (paths.TCP_EVENTS_FILE, "tcp"),
        (paths.TCP_CONNECT_POLICY_FILE, "tetragon"),
        (paths.SSH_SESSIONS_POLICY_FILE, "ssh_exec"),
        (paths.PROCESS_EXEC_POLICY_FILE, "process_exec"),
        (paths.PROCESS_EXIT_POLICY_FILE, "process_exit"),
        (paths.SENSITIVE_FILE_ACCESS_POLICY_FILE, "file_access"),
        (paths.SUDO_EXEC_POLICY_FILE, "sudo_exec"),
        (paths.HTTP_EVENTS_FILE, "http"),
    ]

    counts = {"dns": 0, "tls": 0, "ssh": 0, "tetragon": 0, "ssh_exec": 0, "tcp": 0,
              "process_exec": 0, "process_exit": 0, "file_access": 0, "sudo_exec": 0,
              "http": 0}

    for path, source in sources:
        if not path.exists():
            print(f"[normalizer] skip (missing): {path}")
            continue
        counts[source] += normalize_file(path, source)

    counts["dns"] = normalize_dns_file(paths.DNS_EVENTS_FILE)
    capability_count = normalize_capability_file(paths.CAPABILITY_CHANGE_POLICY_FILE)

    total = sum(counts.values()) + capability_count
    print(f"DNS      : {counts['dns']} events")
    print(f"TLS      : {counts['tls']} events")
    print(f"SSH      : {counts['ssh']} events")
    print(f"TCP      : {counts['tcp']} events")
    print(f"Tetragon : {counts['tetragon']} events")
    print(f"SSH exec : {counts['ssh_exec']} events")
    print(f"Process exec : {counts['process_exec']} events")
    print(f"Process exit : {counts['process_exit']} events")
    print(f"Sensitive file access : {counts['file_access']} events")
    print(f"Sudo exec : {counts['sudo_exec']} events")
    print(f"HTTP     : {counts['http']} events")
    print(f"Capability use (aggregated) : {capability_count} events")
    print(f"Total    : {total}")
    print(f"-> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
