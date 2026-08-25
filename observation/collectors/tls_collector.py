import json
from datetime import datetime, timezone
from scapy.all import sniff, TCP, IP, IPv6
from observation.collectors.ja4 import compute_ja4
from observation import paths

OUTPUT_FILE = paths.TLS_EVENTS_FILE

def ensure_output_dir():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

TLS_HANDSHAKE_CONTENT_TYPE = 0x16
TLS_CLIENTHELLO_TYPE = 0x01

EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000a
EXT_EC_POINT_FORMATS = 0x000b
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002b

def packet_timestamp(packet):
    return datetime.fromtimestamp(
        float(packet.time),
        tz=timezone.utc,
    ).isoformat()

def write_event(event: dict) -> None:
    """Append a single JSON event to tls_events.jsonl."""
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def reset_output_file() -> None:
    OUTPUT_FILE.write_text("", encoding="utf-8")

def get_ip_layer(packet):
    """Return the IPv4 or IPv6 layer, whichever is present."""
    return packet.getlayer(IP) or packet.getlayer(IPv6)


def get_ports(packet):
    return packet[TCP].sport, packet[TCP].dport


def get_clienthello_bytes(packet):
    payload = bytes(packet[TCP].payload)
    if len(payload) < 6:
        return None

    if payload[0] != TLS_HANDSHAKE_CONTENT_TYPE:
        return None

    handshake = payload[5:]
    if len(handshake) < 4 or handshake[0] != TLS_CLIENTHELLO_TYPE:
        return None

    return handshake


def _parse_clienthello_fields(handshake: bytes) -> dict:
    pos = 4  # skip handshake type(1) + length(3)
    tls_version = int.from_bytes(handshake[pos:pos + 2], "big")
    pos += 2
    pos += 32  # random
    session_id_len = handshake[pos]
    pos += 1 + session_id_len
    cipher_len = int.from_bytes(handshake[pos:pos + 2], "big")
    pos += 2
    ciphers = [
        int.from_bytes(handshake[pos + i:pos + i + 2], "big")
        for i in range(0, cipher_len, 2)
    ]
    pos += cipher_len
    comp_len = handshake[pos]
    pos += 1 + comp_len
    fields = {
        "tls_version": tls_version,
        "ciphers": ciphers,
        "extensions": [],
        "sni": None,
        "supported_groups": [],
        "ec_point_formats": [],
        "alpn": [],
        "signature_algorithms": [],
        "supported_versions": [],
    }

    if pos >= len(handshake):
        return fields

    ext_total_len = int.from_bytes(handshake[pos:pos + 2], "big")
    pos += 2
    end = pos + ext_total_len

    while pos + 4 <= end:
        ext_type = int.from_bytes(handshake[pos:pos + 2], "big")
        ext_len = int.from_bytes(handshake[pos + 2:pos + 4], "big")
        ext_data = handshake[pos + 4: pos + 4 + ext_len]
        fields["extensions"].append(ext_type)

        if ext_type == EXT_SERVER_NAME and len(ext_data) >= 5:
            name_len = int.from_bytes(ext_data[3:5], "big")
            fields["sni"] = ext_data[5:5 + name_len].decode(errors="ignore")

        elif ext_type == EXT_SUPPORTED_GROUPS and len(ext_data) >= 2:
            list_len = int.from_bytes(ext_data[0:2], "big")
            fields["supported_groups"] = [
                int.from_bytes(ext_data[2 + i:4 + i], "big")
                for i in range(0, list_len, 2)
            ]

        elif ext_type == EXT_EC_POINT_FORMATS and len(ext_data) >= 1:
            fmt_len = ext_data[0]
            fields["ec_point_formats"] = list(ext_data[1:1 + fmt_len])

        elif ext_type == EXT_ALPN and len(ext_data) >= 2:
            list_len = int.from_bytes(ext_data[0:2], "big")
            protocols = []
            p = 2
            list_end = 2 + list_len
            while p < list_end:
                proto_len = ext_data[p]
                p += 1
                protocols.append(ext_data[p:p + proto_len].decode(errors="ignore"))
                p += proto_len
            fields["alpn"] = protocols

        elif ext_type == EXT_SIGNATURE_ALGORITHMS and len(ext_data) >= 2:
            list_len = int.from_bytes(ext_data[0:2], "big")
            fields["signature_algorithms"] = [
                int.from_bytes(ext_data[2 + i:4 + i], "big")
                for i in range(0, list_len, 2)
            ]

        elif ext_type == EXT_SUPPORTED_VERSIONS and len(ext_data) >= 1:
            list_len = ext_data[0]
            fields["supported_versions"] = [
                int.from_bytes(ext_data[1 + i:3 + i], "big")
                for i in range(0, list_len, 2)
            ]

        pos += 4 + ext_len

    return fields

def extract_sni(fields):
    return fields["sni"]


def extract_cipher_suites(fields):
    return fields["ciphers"]


def extract_extensions(fields):
    return fields["extensions"]


def extract_supported_groups(fields):
    return fields["supported_groups"]


def extract_ec_point_formats(fields):
    return fields["ec_point_formats"]


def extract_alpn(fields):
    return fields["alpn"]


def extract_signature_algorithms(fields):
    return fields["signature_algorithms"]


def extract_supported_versions(fields):
    return fields["supported_versions"]

def build_tls_event(handshake: bytes, ip, ports, timestamp):
    src_port, dst_port = ports
    fields = _parse_clienthello_fields(handshake)

    ja4 = compute_ja4(
        ciphers=extract_cipher_suites(fields),
        extensions=extract_extensions(fields),
        sni_present=extract_sni(fields) is not None,
        alpn=extract_alpn(fields),
        signature_algorithms=extract_signature_algorithms(fields),
        legacy_version=fields["tls_version"],
        supported_versions=extract_supported_versions(fields),
    )

    return {
        "timestamp": timestamp,
        "event_type": "tls_client_hello",
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "transport": "tcp",
        "direction": "outbound",
        "tls_version": fields["tls_version"],
        "sni": extract_sni(fields),
        "cipher_suites": extract_cipher_suites(fields),
        "extensions": extract_extensions(fields),
        "supported_groups": extract_supported_groups(fields),
        "ec_point_formats": extract_ec_point_formats(fields),
        "alpn": extract_alpn(fields),
        "signature_algorithms": extract_signature_algorithms(fields),
        "supported_versions": extract_supported_versions(fields),
        "ja4": ja4["ja4"],
        "ja4_a": ja4["ja4_a"],
        "ja4_b": ja4["ja4_b"],
        "ja4_c": ja4["ja4_c"],
        "raw_clienthello_hex": handshake.hex(),
    }

def handle_packet(packet):
    if not packet.haslayer(TCP):
        return

    handshake = get_clienthello_bytes(packet)
    if handshake is None:
        return

    ip = get_ip_layer(packet)
    if ip is None:
        return

    ports = get_ports(packet)

    try:
        event = build_tls_event(handshake, ip, ports, packet_timestamp(packet))
    except (IndexError, ValueError):
        # Malformed / truncated ClientHello (e.g. segmented across packets) — skip rather than crash the collector.
        return

    write_event(event)
    print(
        f"[TLS CLIENTHELLO] {event['sni']} "
        f"({event['src_ip']}:{event['src_port']} -> {event['dst_ip']}:{event['dst_port']}) "
        f"ja4={event['ja4']}"
    )

def main():
    print("Starting TLS collector...")
    reset_output_file()
    try:
        sniff(
            filter="tcp port 443",
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[TLS] Collector stopped.")

if __name__ == "__main__":
    main()
