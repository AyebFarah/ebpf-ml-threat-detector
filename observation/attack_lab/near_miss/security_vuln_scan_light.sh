#!/usr/bin/env bash
# Simulates an authorized, light vulnerability scan by a known security operator.
set -euo pipefail

TARGET_HOSTS="${1:?Usage: security_vuln_scan_light.sh <space_separated_ips_in_quotes>}"

echo "=== security_vuln_scan_light (near miss, benign) ==="
echo "start_ts=$(date -Iseconds)"

for host in $TARGET_HOSTS; do
    nmap -sV --script vuln -T2 "$host" > /dev/null 2>&1 || true
    sleep 10
done

echo "end_ts=$(date -Iseconds)"
echo "=== security_vuln_scan_light complete ==="