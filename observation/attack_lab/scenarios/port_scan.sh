#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="${1:?Usage: port_scan.sh <victim_ip> <low|medium|high>}"
INTENSITY="${2:-medium}"

case "$INTENSITY" in
  low)    SCAN_ARGS="-sT -T2 --top-ports 100"  ;;
  medium) SCAN_ARGS="-sT -T4 --top-ports 1000" ;;
  high)   SCAN_ARGS="-sS -T5 -p-"              ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== port_scan ($INTENSITY) ==="
echo "target=${VICTIM_IP} args='${SCAN_ARGS}'"
echo "start_ts=$(date -Iseconds)"

nmap $SCAN_ARGS "$VICTIM_IP"

echo "end_ts=$(date -Iseconds)"
echo "=== port_scan complete ==="