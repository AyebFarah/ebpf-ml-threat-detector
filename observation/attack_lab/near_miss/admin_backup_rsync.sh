#!/usr/bin/env bash
# Simulates a regular admin backup job, legitimate large outbound transfer.
set -euo pipefail

BACKUP_HOST="${1:?Usage: admin_backup_rsync.sh <backup_host> <remote_user>}"
REMOTE_USER="${2:?Usage: admin_backup_rsync.sh <backup_host> <remote_user>}"

echo "=== admin_backup_rsync (near miss, benign) ==="
echo "start_ts=$(date -Iseconds)"

rsync -avz -e "ssh -o StrictHostKeyChecking=no" \
    /home /var/www \
    "${REMOTE_USER}@${BACKUP_HOST}:/backups/" > /dev/null 2>&1 || true

echo "end_ts=$(date -Iseconds)"
echo "=== admin_backup_rsync complete ==="