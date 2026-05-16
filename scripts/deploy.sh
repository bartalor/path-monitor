#!/usr/bin/env bash
# Install path-monitor on a fresh Linux box.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

apt_install() {
    sudo apt-get update
    sudo apt-get install -y sqlite3 python3 python3-pip python3-venv \
        iptables iproute2 tcpdump libcap2-bin
}

python_env() {
    python3 -m venv "$ROOT/.venv"
    "$ROOT/.venv/bin/pip" install --upgrade pip
    "$ROOT/.venv/bin/pip" install -r "$ROOT/requirements.txt"
}

grant_caps() {
    # Raw ICMP sockets need CAP_NET_RAW. Grant it on the venv python so the
    # prober can run without root.
    local py
    py="$(readlink -f "$ROOT/.venv/bin/python3")"
    sudo setcap cap_net_raw=eip "$py"
    echo "granted CAP_NET_RAW to $py"
}

if command -v apt-get >/dev/null 2>&1; then
    apt_install
else
    echo "non-apt system: install sqlite3 + python3 + libcap manually" >&2
fi

python_env
grant_caps
"$ROOT/scripts/setup.sh"

cat <<EOF

deploy complete.

Run with:
  source .venv/bin/activate
  python -m orchestrator run --config config/path_monitor.yaml
EOF
