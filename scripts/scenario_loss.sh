#!/usr/bin/env bash
# Inject probabilistic packet loss to a target for N seconds, then restore.
# Usage: scenario_loss.sh <target-ip> [duration_s] [probability]
set -euo pipefail

TARGET="${1:?usage: scenario_loss.sh <target-ip> [duration_s] [probability]}"
DURATION="${2:-60}"
PROB="${3:-0.2}"

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (iptables)" >&2
    exit 1
fi

RULE=(OUTPUT -d "$TARGET" -m statistic --mode random --probability "$PROB" -j DROP)

cleanup() {
    iptables -D "${RULE[@]}" 2>/dev/null || true
    echo "removed loss rule for $TARGET"
}
trap cleanup EXIT INT TERM

iptables -I "${RULE[@]}"
echo "injecting $PROB loss to $TARGET for ${DURATION}s"
sleep "$DURATION"
