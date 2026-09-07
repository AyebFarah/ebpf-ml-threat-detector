#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:?Usage: dns_tunneling.sh <domain> <low|medium|high>}"
INTENSITY="${2:-medium}"

case "$INTENSITY" in
  low)    COUNT=50;  DELAY=0.2  ;;
  medium) COUNT=200; DELAY=0.05 ;;
  high)   COUNT=800; DELAY=0.01 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== dns_tunneling ($INTENSITY) ==="
echo "domain=${DOMAIN} count=${COUNT} delay=${DELAY}"
echo "start_ts=$(date -Iseconds)"

for i in $(seq 1 "$COUNT"); do
    PAYLOAD=$(head -c 24 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z')
    dig +short "${PAYLOAD}.${DOMAIN}" > /dev/null 2>&1 || true
    sleep "$DELAY"
done

echo "end_ts=$(date -Iseconds)"
echo "=== dns_tunneling complete ==="