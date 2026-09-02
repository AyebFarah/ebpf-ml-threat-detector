#!/usr/bin/env bash
# Simulates a dev/deploy script doing rapid legitimate service-discovery
# DNS queries (e.g. resolving many microservice hostnames at startup) —
# high query rate, but real, non-random, non-tunneling-shaped domains.
set -euo pipefail

DOMAIN_SUFFIX="${1:?Usage: dev_dns_burst.sh <domain-suffix e.g. internal.svc>}"

echo "=== dev_dns_burst (near-miss, benign) ==="
echo "start_ts=$(date -Iseconds)"

SERVICES=(auth billing users orders inventory notifications gateway cache
          search analytics scheduler)
for svc in "${SERVICES[@]}"; do
    dig +short "${svc}.${DOMAIN_SUFFIX}" > /dev/null 2>&1 || true
    sleep 0.1
done

echo "end_ts=$(date -Iseconds)"
echo "=== dev_dns_burst complete ==="