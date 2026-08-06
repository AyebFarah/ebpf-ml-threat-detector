import json
from pathlib import Path
from datetime import datetime, timezone

from scapy.all import sniff, DNS, DNSQR, DNSRR, UDP, TCP, IP, IPv6

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "samples" / "collectors_events"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE = OUTPUT_DIR / "dns_events.jsonl"

DNS_PORT = 53

def current_timestamp():
    return datetime.now(timezone.utc).isoformat()

def write_event(event: dict) -> None:
    """Append a single JSON event to dns_events.jsonl."""
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def get_ip_layer(packet):
    """Return the IPv4 or IPv6 layer, whichever is present."""
    return packet.getlayer(IP) or packet.getlayer(IPv6)


def get_transport(packet):
    """Return 'udp', 'tcp', or None if neither is present."""
    if packet.haslayer(UDP):
        return "udp"
    if packet.haslayer(TCP):
        return "tcp"
    return None


def get_ports(packet, transport):
    layer = packet[UDP] if transport == "udp" else packet[TCP]
    return layer.sport, layer.dport


def get_direction(src_port, dst_port):
    """
    Queries go TO port 53 -> outbound.
    Responses come FROM port 53 -> inbound.
    """
    if dst_port == DNS_PORT:
        return "outbound"
    if src_port == DNS_PORT:
        return "inbound"
    return None


def get_dns_layer(packet, transport):
    """
    Return a parsed DNS layer regardless of transport.
    """
    if packet.haslayer(DNS):
        return packet[DNS]

    if transport == "tcp":
        payload = bytes(packet[TCP].payload)
        if len(payload) > 2:
            try:
                return DNS(payload[2:])
            except Exception:
                return None

    return None

def build_query_event(dns, ip, transport, ports):
    src_port, dst_port = ports
    return {
        "timestamp": current_timestamp(),
        "event_type": "dns_query",
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "transport": transport,
        "direction": get_direction(src_port, dst_port),
        "query_name": dns[DNSQR].qname.decode(errors="ignore").rstrip("."),
        "query_type": dns[DNSQR].qtype,
        "transaction_id": dns.id,
    }

RR_TYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    28: "AAAA",
}


def _decode_rdata(rr):
    """Normalize rdata into a plain string regardless of record type."""
    rdata = rr.rdata
    if isinstance(rdata, bytes):
        return rdata.decode(errors="ignore").rstrip(".")
    return str(rdata).rstrip(".") if rr.type in (2, 5, 15) else str(rdata)


def extract_answers(dns):
    """
    Walk the DNS answer record chain and return a normalized list:
    [{"type": "A", "value": "140.82.121.3", "ttl": 300}, ...]
    """
    answers = []
    if not dns.ancount or dns.an is None:
        return answers

    rr = dns.an
    while rr is not None:
        rtype = RR_TYPE_MAP.get(rr.type, str(rr.type))
        answers.append({
            "type": rtype,
            "value": _decode_rdata(rr),
            "ttl": int(rr.ttl),
        })
        rr = rr.payload if isinstance(rr.payload, DNSRR) else None

    return answers


def get_resolved_ip(answers):
    """First A or AAAA answer's value, or None if there isn't one."""
    for a in answers:
        if a["type"] in ("A", "AAAA"):
            return a["value"]
    return None

def build_response_event(dns, ip, transport, ports):
    src_port, dst_port = ports
    answers = extract_answers(dns)

    query_name = None
    if dns.qdcount and dns.qd is not None:
        query_name = dns.qd.qname.decode(errors="ignore").rstrip(".")

    return {
        "timestamp": current_timestamp(),
        "event_type": "dns_response",
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "transport": transport,
        "direction": get_direction(src_port, dst_port),
        "transaction_id": dns.id,
        "rcode": dns.rcode,
        "query_name": query_name,
        "answer_count": dns.ancount,
        "answers": answers,
        "resolved_ip": get_resolved_ip(answers),
    }

def handle_packet(packet):
    transport = get_transport(packet)
    if transport is None:
        return

    dns = get_dns_layer(packet, transport)
    if dns is None or not isinstance(dns, DNS):
        return

    ip = get_ip_layer(packet)
    if ip is None:
        return

    ports = get_ports(packet, transport)

    if dns.qr == 0:
        if not dns.haslayer(DNSQR):
            return
        event = build_query_event(dns, ip, transport, ports)
        write_event(event)
        print(f"[DNS QUERY] {event['query_name']} ({event['src_ip']} -> {event['dst_ip']})")
    else:
        event = build_response_event(dns, ip, transport, ports)
        write_event(event)
        print(
            f"[DNS RESPONSE] {event['query_name']} -> {event['resolved_ip']} "
            f"({event['answer_count']} answers, ttl={event['answers'][0]['ttl'] if event['answers'] else 'n/a'})"
        )

def main():
    print("Starting DNS collector...")
    sniff(
        filter="udp port 53 or tcp port 53",
        prn=handle_packet,
        store=False,
    )


if __name__ == "__main__":
    main()
