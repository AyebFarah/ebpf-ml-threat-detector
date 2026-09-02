#!/usr/bin/env bash
# Simulates a misconfigured backup/monitoring script retrying SSH with a
# WRONG but consistent credential — legitimate automation, not an attack.
# Key difference from ssh_bruteforce: single password retried, not a
# wordlist, and much lower rate (a real cron-triggered retry loop, not
# a brute-force burst).
set -euo pipefail

TARGET_IP="${1:?Usage: ssh_retry_storm.sh <target_ip> <username>}"
USERNAME="${2:?Usage: ssh_retry_storm.sh <target_ip> <username>}"

echo "=== ssh_retry_storm (near-miss, benign) ==="
echo "start_ts=$(date -Iseconds)"

for i in $(seq 1 15); do
    sshpass -p "stale_rotated_password" ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=3 "${USERNAME}@${TARGET_IP}" "true" 2>/dev/null || true
    sleep 20   # realistic cron-style retry interval, not a burst
done

echo "end_ts=$(date -Iseconds)"
echo "=== ssh_retry_storm complete ==="