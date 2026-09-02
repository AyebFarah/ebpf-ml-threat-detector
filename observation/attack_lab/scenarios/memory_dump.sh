#!/usr/bin/env bash
set -euo pipefail

INTENSITY="${1:-medium}"

case "$INTENSITY" in
  low)    ITER=20;  DELAY=0.3 ;;
  medium) ITER=80;  DELAY=0.1 ;;
  high)   ITER=300; DELAY=0.02 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

DUMPFILE="/tmp/.mem_dump_$$.bin"

echo "=== memory_dump ($INTENSITY) ==="
echo "iterations=${ITER} delay=${DELAY} dumpfile=${DUMPFILE}"
echo "start_ts=$(date -Iseconds)"

for i in $(seq 1 "$ITER"); do
    for pid_dir in /proc/[0-9]*; do
        pid="${pid_dir#/proc/}"
        cat "/proc/${pid}/status" >/dev/null 2>&1 || true
        cat "/proc/${pid}/maps" >/dev/null 2>&1 || true
    done
    head -c 1048576 /dev/urandom >> "$DUMPFILE" 2>/dev/null || true
    sleep "$DELAY"
done

rm -f "$DUMPFILE"

echo "end_ts=$(date -Iseconds)"
echo "=== memory_dump complete ==="