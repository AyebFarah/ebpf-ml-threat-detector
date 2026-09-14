#!/usr/bin/env bash
# Simulates a sysadmin running nmap for legitimate inventory/asset
# discovery on their own subnet — looks like a scan, is benign intent.
set -euo pipefail

SUBNET="${1:?Usage: admin_nmap_inventory.sh <subnet-cidr>}"

echo "=== admin_nmap_inventory (near-miss, benign) ==="
echo "start_ts=$(date -Iseconds)"

nmap -sn "$SUBNET"          # ping sweep, not a port scan
nmap -sT --top-ports 20 "$SUBNET"   # light service check, common ports only

echo "end_ts=$(date -Iseconds)"
echo "=== admin_nmap_inventory complete ==="