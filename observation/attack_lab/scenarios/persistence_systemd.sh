#!/usr/bin/env bash
set -euo pipefail

INTENSITY="${1:-medium}"
SERVICE_NAME="backdoor-sim.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
BEACON_SCRIPT="/usr/local/bin/.svc_beacon.sh"

case "$INTENSITY" in
  low)    RUNTIME=30  ;;
  medium) RUNTIME=90  ;;
  high)   RUNTIME=180 ;;
  *) echo "intensity must be low|medium|high"; exit 1 ;;
esac

echo "=== persistence_systemd ($INTENSITY) ==="
echo "service=${SERVICE_NAME} runtime=${RUNTIME}s"
echo "start_ts=$(date -Iseconds)"

sudo tee "$BEACON_SCRIPT" > /dev/null << 'EOF'
#!/usr/bin/env bash
while true; do
    date >> /tmp/.svc_beacon.log
    sleep 15
done
EOF
sudo chmod +x "$BEACON_SCRIPT"

sudo tee "$SERVICE_PATH" > /dev/null << EOF
[Unit]
Description=Simulated backdoor service (attack lab, benign harness)

[Service]
ExecStart=${BEACON_SCRIPT}
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
sudo systemctl start "$SERVICE_NAME"

sleep "$RUNTIME"

sudo systemctl stop "$SERVICE_NAME" || true
sudo systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
sudo rm -f "$SERVICE_PATH" "$BEACON_SCRIPT" /tmp/.svc_beacon.log
sudo systemctl daemon-reload

echo "end_ts=$(date -Iseconds)"
echo "=== persistence_systemd complete ==="