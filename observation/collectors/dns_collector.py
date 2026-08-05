#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime, timezone
from scapy.all import sniff, DNS, DNSQR, UDP, IP, IPv6

OUTPUT = Path("observation/samples/collectors_events/dns_events.jsonl")
OUTPUT.parent.mkdir(parents=True, exist_ok=True)


def build_event(packet):
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "dns_query",
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": packet[UDP].sport,
        "dst_port": packet[UDP].dport,
        "transport": "udp",
        "query_name": packet[DNSQR].qname.decode(
            errors="ignore"
        ).rstrip("."),
        "query_type": packet[DNSQR].qtype,
        "transaction_id": packet[DNS].id
    }


def handle(packet):
    if not packet.haslayer(DNS):
        return

    if not packet.haslayer(DNSQR):
        return

    if packet[DNS].qr != 0:
        return

    event = build_event(packet)
    with OUTPUT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
    print(
        f"[DNS] {event['query_name']} "
        f"({event['src_ip']} -> {event['dst_ip']})"
    )


def main():
    print("Starting DNS collector...")
    sniff(
        filter="udp port 53 or tcp port 53",
        prn=handle,
        store=False
    )


if __name__ == "__main__":
    main()
