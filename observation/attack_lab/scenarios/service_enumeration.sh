#!/usr/bin/env bash
set -euo pipefail

INTENSITY="${1:-medium}"

case "$INTENSITY" in
  low)    ROUNDS=1 ;;
  medium) ROUNDS=3 ;;
  high)   ROUNDS=8 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== service_enumeration ($INTENSITY) ==="
echo "rounds=${ROUNDS}"
echo "start_ts=$(date -Iseconds)"

for i in $(seq 1 "$ROUNDS"); do
    uname -a > /dev/null 2>&1 || true
    cat /etc/os-release > /dev/null 2>&1 || true
    ps aux > /dev/null 2>&1 || true
    top -bn1 > /dev/null 2>&1 || true
    cat /etc/hosts > /dev/null 2>&1 || true
    cat /etc/resolv.conf > /dev/null 2>&1 || true
    sleep 2
done

echo "end_ts=$(date -Iseconds)"
echo "=== service_enumeration complete ==="