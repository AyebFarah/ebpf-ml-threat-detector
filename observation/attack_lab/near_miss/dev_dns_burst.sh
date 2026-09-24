#!/usr/bin/env bash
set -u

DOMAIN_SUFFIX="${1:?Usage: dev_dns_burst_local.sh <domain-suffix>}"

SERVICES=(
    auth billing users orders inventory notifications
    gateway cache search analytics scheduler
)

echo "=== local dev DNS burst ==="
echo "suffix=${DOMAIN_SUFFIX}"
echo "start_ts=$(date -Iseconds)"

for svc in "${SERVICES[@]}"; do
    fqdn="${svc}.${DOMAIN_SUFFIX}"

    if dig +time=1 +tries=1 +short "$fqdn" \
        >/dev/null 2>&1; then
        echo "[dns-completed] ${fqdn}"
    else
        echo "[dns-failed] ${fqdn}"
    fi

    sleep 0.1
done

echo "end_ts=$(date -Iseconds)"
echo "=== local dev DNS burst complete ==="