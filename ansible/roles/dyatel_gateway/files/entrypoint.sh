#!/bin/bash
set -euo pipefail

CONFIG_FILE="${AWG_CONFIG_FILE:-/etc/amnezia/amneziawg/awg0.conf}"

if [ ! -f "${CONFIG_FILE}" ]; then
    echo "ERROR: Configuration file ${CONFIG_FILE} not found!"
    exit 1
fi

cleanup() {
    echo "Received termination signal. Stopping AmneziaWG..."
    awg-quick down "${CONFIG_FILE}" || true
    exit 0
}

trap cleanup SIGTERM SIGINT

echo "Starting AmneziaWG interface from ${CONFIG_FILE}..."
awg-quick up "${CONFIG_FILE}"

echo "AmneziaWG gateway is active and connected."
# Keep container running and responsive to signals
tail -f /dev/null &
wait $!
