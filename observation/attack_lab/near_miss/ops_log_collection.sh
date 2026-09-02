#!/usr/bin/env bash
# Simulates centralized log collection, legitimate ops automation.
set -euo pipefail

REMOTE_HOSTS="${1:?Usage: ops_log_collection.sh <space_separated_ips_in_quotes> <remote_user>}"
REMOTE_USER="${2:?Usage: ops_log_collection.sh <space_separated_ips_in_quotes> <remote_user>}"

echo "=== ops_log_collection (near miss, benign) ==="
echo "start_ts=$(date -Iseconds)"

WORKDIR="/tmp/.log_collect_$$"
mkdir -p "$WORKDIR"

for host in $REMOTE_HOSTS; do
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "${REMOTE_USER}@${host}" "tar -czf - /var/log 2>/dev/null" \
        > "${WORKDIR}/${host}.tar.gz" 2>/dev/null || true
    sleep 3
done

tar -czf "${WORKDIR}/collected_logs.tar.gz" "$WORKDIR"/*.tar.gz 2>/dev/null || true
rm -rf "$WORKDIR"

echo "end_ts=$(date -Iseconds)"
echo "=== ops_log_collection complete ==="