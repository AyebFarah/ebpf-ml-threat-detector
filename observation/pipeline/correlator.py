import json
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = BASE_DIR / "samples" / "unified_events" / "unified_events.jsonl"
OUTPUT_FILE = BASE_DIR / "samples" / "unified_events" / "correlated_events.jsonl"

DNS_TIME_WINDOW_SECONDS = 5
TLS_TIME_TOLERANCE_SECONDS = 2

DNS_CORRELATION_METHOD = "resolved_ip+time"
TLS_CORRELATION_METHOD = "five_tuple"


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def load_events(path: Path) -> list:
    events = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def split_by_source(events: list):
    dns_responses = [
        e for e in events
        if e["source"] == "dns" and e["event_type"] == "dns_response"
    ]
    tcp_connects = [
        e for e in events
        if e["source"] == "tetragon" and e["event_type"] == "tcp_connect"
    ]
    tls_hellos = [
        e for e in events
        if e["source"] == "tls" and e["event_type"] == "tls_client_hello"
    ]
    return dns_responses, tcp_connects, tls_hellos


def index_dns_by_ip(dns_responses: list) -> dict:
    index = {}
    for dns in dns_responses:
        resolved_ip = dns["extra"].get("resolved_ip")
        if not resolved_ip:
            continue
        index.setdefault(resolved_ip, []).append(dns)

    for ip in index:
        index[ip].sort(key=lambda e: parse_ts(e["timestamp"]))

    return index


def index_tls_by_tuple(tls_hellos: list) -> dict:
    index = {}
    for tls in tls_hellos:
        key = (tls["src_ip"], tls["dst_ip"], tls["src_port"], tls["dst_port"], tls["transport"])
        index.setdefault(key, []).append(tls)

    for key in index:
        index[key].sort(key=lambda e: parse_ts(e["timestamp"]))

    return index


def find_dns_match(tcp_event: dict, dns_index: dict):
    candidates = dns_index.get(tcp_event["dst_ip"], [])
    tcp_ts = parse_ts(tcp_event["timestamp"])

    best, best_delta = None, None
    for dns in candidates:
        delta = (tcp_ts - parse_ts(dns["timestamp"])).total_seconds()
        if 0 <= delta <= DNS_TIME_WINDOW_SECONDS:
            if best is None or delta < best_delta:
                best, best_delta = dns, delta
        elif delta < 0:
            break

    return best, best_delta


def find_tls_match(tcp_event: dict, tls_index: dict):
    key = (
        tcp_event["src_ip"], tcp_event["dst_ip"],
        tcp_event["src_port"], tcp_event["dst_port"],
        tcp_event["transport"],
    )
    candidates = tls_index.get(key, [])
    tcp_ts = parse_ts(tcp_event["timestamp"])

    best, best_delta = None, None
    for tls in candidates:
        delta = abs((parse_ts(tls["timestamp"]) - tcp_ts).total_seconds())
        if delta <= TLS_TIME_TOLERANCE_SECONDS:
            if best is None or delta < best_delta:
                best, best_delta = tls, delta

    return best, best_delta


def build_enriched_event(tcp_event: dict, dns_match, dns_delta, tls_match, tls_delta) -> dict:
    # Keep the complete normalized event (full extra + its own
    # timestamp), not just a hand-picked subset, so nothing collected
    # upstream is lost at this stage.
    dns_block = None
    if dns_match:
        dns_block = dict(dns_match["extra"])
        dns_block["timestamp"] = dns_match["timestamp"]

    tls_block = None
    if tls_match:
        tls_block = dict(tls_match["extra"])
        tls_block["timestamp"] = tls_match["timestamp"]

    return {
        "timestamp": tcp_event["timestamp"],
        "process": tcp_event.get("process"),
        "network": {
            "src_ip": tcp_event["src_ip"],
            "dst_ip": tcp_event["dst_ip"],
            "src_port": tcp_event["src_port"],
            "dst_port": tcp_event["dst_port"],
            "transport": tcp_event["transport"],
            "direction": tcp_event.get("direction"),
        },
        "dns": dns_block,
        "tls": tls_block,
        "correlation": {
            "dns_matched": dns_match is not None,
            "dns_method": DNS_CORRELATION_METHOD,
            "dns_time_delta_ms": round(dns_delta * 1000) if dns_delta is not None else None,
            "tls_matched": tls_match is not None,
            "tls_method": TLS_CORRELATION_METHOD,
            "tls_time_delta_ms": round(tls_delta * 1000) if tls_delta is not None else None,
        },
    }


def correlate(events: list) -> list:
    dns_responses, tcp_connects, tls_hellos = split_by_source(events)
    dns_index = index_dns_by_ip(dns_responses)
    tls_index = index_tls_by_tuple(tls_hellos)

    enriched = []
    for tcp_event in tcp_connects:
        dns_match, dns_delta = find_dns_match(tcp_event, dns_index)
        tls_match, tls_delta = find_tls_match(tcp_event, tls_index)
        enriched.append(
            build_enriched_event(tcp_event, dns_match, dns_delta, tls_match, tls_delta)
        )

    return enriched


def main():
    events = load_events(INPUT_FILE)
    events.sort(key=lambda e: parse_ts(e["timestamp"]))
    enriched = correlate(events)

    with OUTPUT_FILE.open("w", encoding="utf-8") as f:
        for e in enriched:
            f.write(json.dumps(e) + "\n")

    with_dns = sum(1 for e in enriched if e["correlation"]["dns_matched"])
    with_tls = sum(1 for e in enriched if e["correlation"]["tls_matched"])
    print(f"[correlator] {len(enriched)} tcp_connect events processed")
    print(f"[correlator] {with_dns} matched to a DNS response")
    print(f"[correlator] {with_tls} matched to a TLS ClientHello")
    print(f"[correlator] output -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
