#!/usr/bin/env python3
"""
Simulated DNS tunneling client. One process, standard library only.
Usage: dns_tunneling.py <resolver_ip> <domain> <low|medium|high> [port]
"""
import base64
import os
import random
import socket
import struct
import sys
import time
from datetime import datetime

PROFILES = {
    "low":    (50, 0.20),
    "medium": (200, 0.05),
    "high":   (800, 0.01),
}


def build_query(qname: str, txid: int) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)   # one question, recursion desired
    question = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    question += struct.pack(">HH", 1, 1)                        # type A, class IN
    return header + question


def random_label() -> str:
    # 24 random bytes as base32 gives 39 characters from a to z and 2 to 7, like real tunnel payloads
    return base64.b32encode(os.urandom(24)).decode().lower().rstrip("=")


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[3] not in PROFILES:
        print("Usage: dns_tunneling.py <resolver_ip> <domain> <low|medium|high> [port]")
        return 1
    resolver, domain, intensity = sys.argv[1], sys.argv[2], sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 53
    count, delay = PROFILES[intensity]

    print(f"=== dns_tunneling ({intensity}) ===")
    print(f"resolver={resolver}:{port} domain={domain} count={count} delay={delay}")
    print(f"start_ts={datetime.now().astimezone().isoformat(timespec='seconds')}", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.connect((resolver, port))   # connected UDP: a closed port raises an error instead of hanging

    answered = nxdomain = refused = timeouts = 0
    for _ in range(count):
        try:
            sock.send(build_query(f"{random_label()}.{domain}", random.randint(0, 65535)))
            reply = sock.recv(512)
            answered += 1
            if reply[3] & 0x0F == 3:
                nxdomain += 1
        except ConnectionRefusedError:
            refused += 1
        except socket.timeout:
            timeouts += 1
        time.sleep(delay)

    print(f"sent={count} answered={answered} nxdomain={nxdomain} refused={refused} timeouts={timeouts}")
    print(f"end_ts={datetime.now().astimezone().isoformat(timespec='seconds')}")
    print("=== dns_tunneling complete ===")
    return 0 if answered > 0 else 2   # a run where nothing answered must not look successful


if __name__ == "__main__":
    sys.exit(main())