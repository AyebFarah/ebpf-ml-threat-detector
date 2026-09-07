#!/usr/bin/env bash
set -euo pipefail

SUBNET="${1:?Usage: network_discovery.sh <subnet_cidr> <low|medium|high>}"
INTENSITY="${2:-medium}"

case "$INTENSITY" in
  low)    TOP_PORTS=20  ;;
  medium) TOP_PORTS=100 ;;
  high)   TOP_PORTS=500 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== network_discovery ($INTENSITY) ==="
echo "subnet=${SUBNET} top_ports=${TOP_PORTS}"
echo "start_ts=$(date -Iseconds)"

nmap -sn "$SUBNET" -oG - 2>/dev/null | awk '/Up$/{print $2}' > /tmp/.live_hosts.txt || true

while read -r host; do
    nmap -sV --top-ports "$TOP_PORTS" "$host" > /dev/null 2>&1 || true
done < /tmp/.live_hosts.txt

netstat -tulpn > /dev/null 2>&1 || true
ss -tulpn > /dev/null 2>&1 || true
ip neigh > /dev/null 2>&1 || true
arp -a > /dev/null 2>&1 || true

rm -f /tmp/.live_hosts.txt

echo "end_ts=$(date -Iseconds)"
echo "=== network_discovery complete ==="