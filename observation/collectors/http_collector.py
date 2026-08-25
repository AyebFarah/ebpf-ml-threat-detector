import hashlib
import json
import re
import traceback
from datetime import datetime, timezone
from scapy.all import sniff, TCP, IP, IPv6, Raw
from observation import paths

OUTPUT_FILE = paths.HTTP_EVENTS_FILE

def ensure_output_dir():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

HTTP_PORT = 80

REQUEST_LINE_RE = re.compile(
    rb"^(?P<method>[A-Z]{3,10}) (?P<path>\S+) HTTP/(?P<version>\d\.\d)\r\n"
)
RESPONSE_LINE_RE = re.compile(
    rb"^HTTP/(?P<version>\d\.\d) (?P<status>\d{3}) "
)
HEADER_LINE_RE = re.compile(rb"^([^:\r\n]+):\s*(.*?)\r\n", re.MULTILINE)


def packet_timestamp(packet):
    return datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat()


def write_event(event: dict) -> None:
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def reset_output_file() -> None:
    OUTPUT_FILE.write_text("", encoding="utf-8")


def get_ip_layer(packet):
    return packet.getlayer(IP) or packet.getlayer(IPv6)


def hash_value(value: str) -> str:
    """
    One-way hash for privacy-sensitive fields (path, user-agent). Keeps
    them usable as ML categorical features (same path -> same hash, so
    frequency/novelty features still work) without persisting the raw
    string, per the doc's 'hashed path' / 'hashed user-agent' guidance.
    """
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:16]


def parse_headers(header_block: bytes) -> dict:
    headers = {}
    for match in HEADER_LINE_RE.finditer(header_block):
        key = match.group(1).decode(errors="ignore").strip().lower()
        value = match.group(2).decode(errors="ignore").strip()
        headers[key] = value
    return headers


def split_head(payload: bytes):
    """
    Return (head_bytes, found) where head_bytes is everything up to and
    including the blank line that terminates HTTP headers. found=False
    if this packet doesn't contain a complete header block (e.g. it's a
    body-only continuation segment) -- we skip those rather than
    reassembling, per the 'no payload capture' scope decision.
    """
    idx = payload.find(b"\r\n\r\n")
    if idx == -1:
        return None, False
    return payload[: idx + 4], True


def build_request_event(head: bytes, headers: dict, ip, ports, transport, timestamp):
    match = REQUEST_LINE_RE.match(head)
    if not match:
        return None
    src_port, dst_port = ports
    path = match.group("path").decode(errors="ignore")
    return {
        "timestamp": timestamp,
        "event_type": "http_request",
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "transport": transport,
        "direction": "outbound" if dst_port == HTTP_PORT else "inbound",
        "method": match.group("method").decode(errors="ignore"),
        "http_version": match.group("version").decode(errors="ignore"),
        "host": headers.get("host"),
        "path_hash": hash_value(path),
        "path_length": len(path),
        "user_agent_hash": hash_value(headers["user-agent"]) if "user-agent" in headers else None,
        "content_length": int(headers["content-length"]) if headers.get("content-length", "").isdigit() else None,
    }


def build_response_event(head: bytes, headers: dict, ip, ports, transport, timestamp):
    match = RESPONSE_LINE_RE.match(head)
    if not match:
        return None
    src_port, dst_port = ports
    return {
        "timestamp": timestamp,
        "event_type": "http_response",
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "transport": transport,
        "direction": "inbound" if src_port == HTTP_PORT else "outbound",
        "status_code": int(match.group("status")),
        "http_version": match.group("version").decode(errors="ignore"),
        "content_length": int(headers["content-length"]) if headers.get("content-length", "").isdigit() else None,
        "content_type": headers.get("content-type"),
    }


def handle_packet(packet):
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return
    ip = get_ip_layer(packet)
    if ip is None:
        return

    tcp = packet[TCP]
    src_port, dst_port = tcp.sport, tcp.dport
    if src_port != HTTP_PORT and dst_port != HTTP_PORT:
        return

    payload = bytes(packet[Raw].load)
    head, found = split_head(payload)
    if not found:
        return

    try:
        headers = parse_headers(head)
        timestamp = packet_timestamp(packet)
        ports = (src_port, dst_port)

        if dst_port == HTTP_PORT:
            event = build_request_event(head, headers, ip, ports, "tcp", timestamp)
            if event:
                write_event(event)
                print(f"[HTTP REQUEST] {event['method']} {event['host'] or ip.dst} "
                      f"({ip.src}:{src_port} -> {ip.dst}:{dst_port})")
        else:
            event = build_response_event(head, headers, ip, ports, "tcp", timestamp)
            if event:
                write_event(event)
                print(f"[HTTP RESPONSE] {event['status_code']} "
                      f"({ip.src}:{src_port} -> {ip.dst}:{dst_port})")

    except Exception:
        print("[HTTP] ERROR while handling packet:")
        traceback.print_exc()


def main():
    print("Starting HTTP collector...")
    reset_output_file()
    try:
        sniff(
            filter=f"tcp port {HTTP_PORT}",
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[HTTP] Collector stopped.")


if __name__ == "__main__":
    main()