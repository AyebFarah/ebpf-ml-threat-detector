import json
import traceback
import threading
from datetime import datetime, timezone
from scapy.all import sniff, TCP, IP, IPv6
from .. import paths

OUTPUT_FILE = paths.TCP_EVENTS_FILE

def ensure_output_dir():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20

# Order matters only for the human-readable label below.
FLAG_NAME_BITS = [
    (FLAG_SYN, "SYN"), (FLAG_ACK, "ACK"), (FLAG_FIN, "FIN"),
    (FLAG_RST, "RST"), (FLAG_PSH, "PSH"), (FLAG_URG, "URG"),
]

IDLE_TIMEOUT_SECONDS = 120
# Scanning the whole flow table on every packet is wasteful under load, so we only sweep for idle flows every N packets processed.
SWEEP_INTERVAL_PACKETS = 200

_flows = {}
_packet_counter = 0


def packet_timestamp(packet):
    return datetime.fromtimestamp(float(packet.time), tz=timezone.utc).isoformat()


def parse_ts(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def write_event(event: dict) -> None:
    with OUTPUT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def reset_output_file() -> None:
    OUTPUT_FILE.write_text("", encoding="utf-8")


def get_ip_layer(packet):
    return packet.getlayer(IP) or packet.getlayer(IPv6)


def flags_to_str(flags_int: int) -> str:
    names = [name for bit, name in FLAG_NAME_BITS if flags_int & bit]
    return "-".join(names) if names else "NONE"


def get_mss(tcp_layer):
    for opt in tcp_layer.options:
        if opt[0] == "MSS":
            return opt[1]
    return None


def flow_key(ip_a, port_a, ip_b, port_b):
    """
    Canonical, direction-independent key. A SYN and its SYN-ACK reply
    have swapped src/dst, so we sort the endpoint pair rather than
    keying on raw src/dst — otherwise every reply would look like a
    brand-new flow.
    """
    a, b = (ip_a, port_a), (ip_b, port_b)
    return (a, b) if a < b else (b, a)


def new_flow(ip, tcp, timestamp):
    return {
        "initiator": {"ip": ip.src, "port": tcp.sport},
        "responder": {"ip": ip.dst, "port": tcp.dport},
        "start_ts": timestamp,
        "syn_ts": timestamp,
        "synack_ts": None,
        "last_seen": timestamp,
        "state": "syn_sent",
        "handshake_completed": False,
        "syn_count": 1,
        "fin_count": 0,
        "rst_seen": False,
        "packets_out": 0,
        "packets_in": 0,
        "bytes_out": 0,
        "bytes_in": 0,
        "flags_seen": set(),
        "seen_segments_out": set(),
        "seen_segments_in": set(),
        "retransmissions": 0,
        "initial_window_out": tcp.window,
        "initial_window_in": None,
        "mss_out": get_mss(tcp),
        "mss_in": None,
    }


def is_from_initiator(flow, ip, tcp):
    return ip.src == flow["initiator"]["ip"] and tcp.sport == flow["initiator"]["port"]


def update_flow_counters(flow, ip, tcp, packet, timestamp):
    flow["last_seen"] = timestamp
    payload_len = len(bytes(tcp.payload))
    packet_len = len(packet)
    flags_int = int(tcp.flags)
    flow["flags_seen"].add(flags_to_str(flags_int))

    from_initiator = is_from_initiator(flow, ip, tcp)
    if from_initiator:
        flow["packets_out"] += 1
        flow["bytes_out"] += packet_len
        seen = flow["seen_segments_out"]
    else:
        flow["packets_in"] += 1
        flow["bytes_in"] += packet_len
        seen = flow["seen_segments_in"]

    # Retransmission heuristic: same (seq, payload_len) seen twice in the
    # same direction. Doesn't distinguish real retransmits from spurious
    # duplicates (e.g. a link-layer replay), but that distinction isn't
    # observable from a single vantage point anyway.
    if payload_len > 0:
        segment = (tcp.seq, payload_len)
        if segment in seen:
            flow["retransmissions"] += 1
        else:
            seen.add(segment)

    return from_initiator, flags_int


def finalize_flow(flow, end_ts, reason):
    duration = None
    try:
        duration = (parse_ts(end_ts) - parse_ts(flow["start_ts"])).total_seconds()
    except ValueError:
        pass

    handshake_rtt_ms = None
    if flow["synack_ts"]:
        try:
            handshake_rtt_ms = round(
                (parse_ts(flow["synack_ts"]) - parse_ts(flow["syn_ts"])).total_seconds() * 1000, 3
            )
        except ValueError:
            pass

    event = {
        "timestamp": end_ts,
        "event_type": "tcp_flow",
        "src_ip": flow["initiator"]["ip"],
        "dst_ip": flow["responder"]["ip"],
        "src_port": flow["initiator"]["port"],
        "dst_port": flow["responder"]["port"],
        "transport": "tcp",
        "direction": "outbound",
        "start_ts": flow["start_ts"],
        "end_ts": end_ts,
        "duration_seconds": duration,
        "handshake_completed": flow["handshake_completed"],
        "handshake_rtt_ms": handshake_rtt_ms,
        "termination_reason": reason,
        "syn_count": flow["syn_count"],
        "fin_count": flow["fin_count"],
        "rst_seen": flow["rst_seen"],
        "packets_out": flow["packets_out"],
        "packets_in": flow["packets_in"],
        "bytes_out": flow["bytes_out"],
        "bytes_in": flow["bytes_in"],
        "retransmissions": flow["retransmissions"],
        "flags_seen": sorted(flow["flags_seen"]),
        "initial_window_out": flow["initial_window_out"],
        "initial_window_in": flow["initial_window_in"],
        "mss_out": flow["mss_out"],
        "mss_in": flow["mss_in"],
    }
    write_event(event)
    print(
        f"[TCP FLOW] {event['src_ip']}:{event['src_port']} -> "
        f"{event['dst_ip']}:{event['dst_port']} reason={reason} "
        f"dur={duration} pkts={event['packets_out']}/{event['packets_in']} "
        f"bytes={event['bytes_out']}/{event['bytes_in']}"
    )


def sweep_idle_flows(now_ts):
    now = parse_ts(now_ts)
    stale = [
        k for k, f in _flows.items()
        if (now - parse_ts(f["last_seen"])).total_seconds() > IDLE_TIMEOUT_SECONDS
    ]
    for k in stale:
        flow = _flows.pop(k)
        finalize_flow(flow, flow["last_seen"], "timeout")


def flush_all_flows():
    for flow in list(_flows.values()):
        finalize_flow(flow, flow["last_seen"], "collector_stopped")
    _flows.clear()


def handle_packet(packet):
    global _packet_counter

    if not packet.haslayer(TCP):
        return
    ip = get_ip_layer(packet)
    if ip is None:
        return

    try:
        tcp = packet[TCP]
        timestamp = packet_timestamp(packet)
        flags_int = int(tcp.flags)
        is_syn = bool(flags_int & FLAG_SYN)
        is_ack = bool(flags_int & FLAG_ACK)
        is_fin = bool(flags_int & FLAG_FIN)
        is_rst = bool(flags_int & FLAG_RST)

        key = flow_key(ip.src, tcp.sport, ip.dst, tcp.dport)
        flow = _flows.get(key)

        if flow is None:
            if is_syn and not is_ack:
                flow = new_flow(ip, tcp, timestamp)
                _flows[key] = flow
            else:
                # Mid-stream packet for a connection whose SYN we never
                # saw (collector started after it opened). Nothing to
                # attach it to — drop rather than fabricate a start time.
                return
        elif is_syn and not is_ack and is_from_initiator(flow, ip, tcp):
            flow["syn_count"] += 1  # retransmitted SYN, not a new flow

        from_initiator, _ = update_flow_counters(flow, ip, tcp, packet, timestamp)

        if is_syn and is_ack and not from_initiator:
            flow["synack_ts"] = flow["synack_ts"] or timestamp
            flow["initial_window_in"] = flow["initial_window_in"] or tcp.window
            flow["mss_in"] = flow["mss_in"] or get_mss(tcp)

        if is_ack and not is_syn and flow["state"] == "syn_sent" and flow["synack_ts"]:
            flow["state"] = "established"
            flow["handshake_completed"] = True

        if is_rst:
            flow["rst_seen"] = True
            finalize_flow(flow, timestamp, "reset")
            del _flows[key]
        elif is_fin:
            flow["fin_count"] += 1
            if flow["fin_count"] >= 2:
                # Simplification: a real four-way close tracks each
                # side's FIN + final ACK precisely. We just close once
                # we've seen a FIN from both directions — bounds the
                # duration correctly, isn't a strict RFC 793 state
                # machine.
                finalize_flow(flow, timestamp, "fin")
                del _flows[key]

        _packet_counter += 1
        if _packet_counter % SWEEP_INTERVAL_PACKETS == 0:
            sweep_idle_flows(timestamp)

    except Exception:
        print("[TCP] ERROR while handling packet:")
        traceback.print_exc()


def main():
    print("Starting TCP collector...")
    reset_output_file()

    try:
        sniff(
            filter="tcp",
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[TCP] Collector stopped.")
    finally:
        flush_all_flows()


if __name__ == "__main__":
    main()
