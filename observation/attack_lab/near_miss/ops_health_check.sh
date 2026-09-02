#!/usr/bin/env bash
# Simulates a monitoring script checking known hosts on a fixed schedule,
# legitimate ops, not reconnaissance. Fixed host list and predictable
# interval, unlike network_discovery's broad sweep and version probing.
set -euo pipefail

SUBNET_HOSTS="${1:?Usage: ops_health_check.sh <space_separated_ips_in_quotes>}"

echo "=== ops_health_check (near miss, benign) ==="
echo "start_ts=$(date -Iseconds)"

for round in 1 2 3; do
    for host in $SUBNET_HOSTS; do
        ping -c1 -W1 "$host" > /dev/null 2>&1 || true
        curl -s -m 2 "http://${host}:8080/health" > /dev/null 2>&1 || true
    done
    sleep 30
done

echo "end_ts=$(date -Iseconds)"
echo "=== ops_health_check complete ==="