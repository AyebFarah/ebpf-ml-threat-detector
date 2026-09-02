#!/usr/bin/env bash
# Simulates rapid package installation, legitimate dev/deploy activity.
set -euo pipefail

PACKAGES="${1:?Usage: dependency_install_storm.sh \"pkg1 pkg2 pkg3\"}"

echo "=== dependency_install_storm (near miss, benign) ==="
echo "start_ts=$(date -Iseconds)"

VENV_DIR="/tmp/.dep_storm_venv_$$"
python3 -m venv "$VENV_DIR" > /dev/null 2>&1 || true
source "${VENV_DIR}/bin/activate"

for pkg in $PACKAGES; do
    pip install "$pkg" > /dev/null 2>&1 || true
done

deactivate || true
rm -rf "$VENV_DIR"

echo "end_ts=$(date -Iseconds)"
echo "=== dependency_install_storm complete ==="