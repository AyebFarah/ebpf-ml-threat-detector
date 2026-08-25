import json
import socket
import traceback
from datetime import datetime, timezone
from scapy.all import sniff, DNS, DNSQR, DNSRR, UDP, TCP, IP, IPv6
from observation import paths

OUTPUT_FILE = paths.DNS_EVENTS_FILE

def ensure_output_dir():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

DNS_PORT = 53

def packet_timestamp(packet):
    return datetime.fromtimestamp(
        float(packet.time),
        tz=timezone.utc,
    ).isoformat()

def write_event(event: dict) -> None:
    """Append a single JSON event to dns_events.jsonl."""
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def reset_output_file() -> None:
    OUTPUT_FILE.write_text("", encoding="utf-8")

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

def build_query_event(dns, ip, transport, ports, timestamp):
    src_port, dst_port = ports
    return {
        "timestamp": timestamp,
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
    """
    Decode rdata defensively across the record types we care about.

    Scapy normally hands back A/AAAA rdata as an already-formatted
    dotted/colon string, and CNAME/NS/MX rdata as bytes (with name
    compression already resolved). We still add an explicit fallback
    for the case where rdata comes back as a raw 4-byte IP (seen on
    some Scapy versions/record shapes) so an A record never silently
    produces None.
    """
    rdata = getattr(rr, "rdata", None)
    rtype = getattr(rr, "type", None)

    if rdata is None:
        return None

    if isinstance(rdata, bytes):
        if rtype == 1 and len(rdata) == 4:
            # Raw 4-byte A record rdata that wasn't auto-decoded.
            return socket.inet_ntoa(rdata)
        return rdata.decode(errors="ignore").rstrip(".")

    return str(rdata).rstrip(".")

def extract_answers(dns):
    """
    Walk the DNS answer record chain and return a normalized list:
    [{"type": "A", "value": "140.82.121.3", "ttl": 300}, ...]
    """
    answers = []
    if not dns.ancount or dns.an is None:
        return answers

    rr = dns.an
    seen = 0
    while rr is not None and seen < dns.ancount:
        rtype = RR_TYPE_MAP.get(getattr(rr, "type", -1),
                        str(getattr(rr, "type", "UNKNOWN")))
        value = _decode_rdata(rr)
        if value is not None:
            answers.append({
                "type": rtype,
                "value": value,
                "ttl": int(getattr(rr, "ttl", 0)),
    	    })
        else:
            print(
                f"[DNS] WARNING: could not decode rdata for answer "
                f"#{seen} type={rtype!r} raw_type={getattr(rr, 'type', None)!r}"
            )
        rr = rr.payload if isinstance(rr.payload, DNSRR) else None
        seen += 1

    return answers


def get_resolved_ip(answers):
    """First A or AAAA answer's value, or None if there isn't one."""
    for a in answers:
        if a["type"] in ("A", "AAAA"):
            return a["value"]
    return None

def build_response_event(dns, ip, transport, ports, timestamp):
    src_port, dst_port = ports
    answers = extract_answers(dns)

    query_name = None
    if dns.qdcount and dns.qd is not None:
        query_name = dns.qd.qname.decode(errors="ignore").rstrip(".")

    return {
        "timestamp": timestamp,
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

    try:
        if dns.qr == 0:
            if not dns.haslayer(DNSQR):
                return
            event = build_query_event(dns, ip, transport, ports, packet_timestamp(packet))
            write_event(event)
            print(f"[DNS QUERY] {event['query_name']} ({event['src_ip']} -> {event['dst_ip']})")
        else:
            event = build_response_event(dns, ip, transport, ports, packet_timestamp(packet))
            write_event(event)

            if event["resolved_ip"] is None:
                # This is the diagnostic that tells you WHY it's null:
                # rcode != 0 means the server itself returned no answer
                # (NXDOMAIN/SERVFAIL/etc) — that's expected, not a bug.
                # rcode == 0 with answer_count > 0 means answers existed
                # but couldn't be decoded (a real bug, watch stderr for
                # the WARNING lines above).
                # rcode == 0 with answer_count == 0 means the server
                # genuinely returned zero records (e.g. CNAME-only
                # response chain not yet followed, or a query type with
                # no A/AAAA in this response).
                print(
                    f"[DNS RESPONSE] {event['query_name']} -> None "
                    f"(rcode={event['rcode']}, answer_count={event['answer_count']})"
                )
            else:
                print(
                    f"[DNS RESPONSE] {event['query_name']} -> {event['resolved_ip']} "
                    f"({event['answer_count']} answers, ttl={event['answers'][0]['ttl'] if event['answers'] else 'n/a'})"
                )
    except Exception:
        # Previously a parse failure here would be swallowed by Scapy's
        # sniff loop with no clear signal. Surface it instead.
        print("[DNS] ERROR while handling packet:")
        traceback.print_exc()

def main():
    print("Starting DNS collector...")
    reset_output_file()
    try:
        sniff(
            filter="udp port 53 or tcp port 53",
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[DNS] Collector stopped.")

if __name__ == "__main__":
    main()
