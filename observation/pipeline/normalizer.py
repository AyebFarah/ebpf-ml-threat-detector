import json
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


def reset_output_file() -> None:
    OUTPUT_FILE.write_text("", encoding="utf-8")


def write_event(event: dict) -> None:
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def normalize_transport(value):
    if value is None:
        return None
    if isinstance(value, str) and not value.isdigit():
        return value.lower()
    try:
        return PROTOCOL_NUMBER_MAP.get(int(value))
    except (TypeError, ValueError):
        return None


def _split_common_and_extra(raw: dict):
    common = {k: raw.get(k) for k in COMMON_FIELDS}
    common["transport"] = normalize_transport(common.get("transport"))
    extra = {k: v for k, v in raw.items() if k not in COMMON_FIELDS}
    return common, extra

def normalize_dns(raw: dict) -> dict:
    common, extra = _split_common_and_extra(raw)
    return {**common, "source": "dns", "process": None, "extra": extra}


def normalize_tls(raw: dict) -> dict:
    common, extra = _split_common_and_extra(raw)
    return {**common, "source": "tls", "process": None, "extra": extra}


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
    direction = "outbound" if function_name == "tcp_connect" else None

    return {
        "timestamp": raw.get("time"),
        "event_type": function_name,
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


NORMALIZERS = {
    "dns": normalize_dns,
    "tls": normalize_tls,
    "tetragon": normalize_tetragon,
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
            write_event(normalizer_fn(raw))
            count += 1
    return count


def main():
    reset_output_file()
    sources = [
        (SAMPLES_DIR / "collectors_events" / "dns_events.jsonl", "dns"),
        (SAMPLES_DIR / "collectors_events" / "tls_events.jsonl", "tls"),
        (SAMPLES_DIR / "event_logs_by_policy" / "tcp-connect.jsonl", "tetragon"),
    ]

    counts = {"dns": 0, "tls": 0, "tetragon": 0}

    for path, source in sources:
        if not path.exists():
            print(f"[normalizer] skip (missing): {path}")
            continue
        counts[source] = normalize_file(path, source)

    total = sum(counts.values())
    print(f"DNS      : {counts['dns']} events")
    print(f"TLS      : {counts['tls']} events")
    print(f"Tetragon : {counts['tetragon']} events")
    print(f"Total    : {total}")
    print(f"-> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
