#!/usr/bin/env bash
# Temporarily route a target via an alternate gateway, then restore.
# Usage: scenario_route_change.sh <target-ip> <alt-gateway> [duration_s]
set -euo pipefail

TARGET="${1:?usage: scenario_route_change.sh <target-ip> <alt-gateway> [duration_s]}"
ALT_GW="${2:?missing alt-gateway}"
DURATION="${3:-60}"

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (ip route)" >&2
    exit 1
fi

ORIG_ROUTE="$(ip route get "$TARGET" | head -n1 || true)"
echo "original route: $ORIG_ROUTE"

cleanup() {
    ip route del "$TARGET" 2>/dev/null || true
    echo "restored route for $TARGET"
}
trap cleanup EXIT INT TERM

ip route replace "$TARGET" via "$ALT_GW"
echo "routing $TARGET via $ALT_GW for ${DURATION}s"
sleep "$DURATION"
