"""Network-namespace sandbox for integration tests.

Topology per sandbox:

    [host] ──veth── [netns]
     .1                .2 ← responder lives here, prober probes this IP

The host side of the veth gets 10.X.Y.1/30; the netns side 10.X.Y.2/30. The
host probes 10.X.Y.2 — packets traverse the veth, hit `tc netem` (attached to
the host-side veth egress), then the in-netns responder echoes them back.

All `ip`/`tc` invocations are gated by `_run`, which converts
permission errors into `pytest.skip` so non-root runs are tidy.
"""
from __future__ import annotations

import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest


def _skip_if_unsupported() -> None:
    if sys.platform != "linux":
        pytest.skip("integration tests require Linux netns", allow_module_level=False)
    if os.geteuid() != 0:
        pytest.skip("integration tests require root (run: sudo pytest -m integration)")
    for tool in ("ip", "tc"):
        if shutil.which(tool) is None:
            pytest.skip(f"integration tests require `{tool}` in PATH")


def _run(argv: list[str]) -> None:
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(argv)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )


@dataclass(frozen=True)
class Sandbox:
    """Live netns + veth + responder. Use `inject_*` to apply faults."""
    netns: str
    host_veth: str
    peer_veth: str
    host_ip: str
    target_ip: str  # the IP the prober probes
    responder_pid: int

    def inject_loss(self, probability: float) -> None:
        """Drop `probability` (0.0–1.0) of packets on the host→target path."""
        self._set_netem(f"loss {probability * 100:.1f}%")

    def inject_delay_ms(self, ms: int) -> None:
        """Add `ms` milliseconds of latency on the host→target path."""
        self._set_netem(f"delay {ms}ms")

    def clear_faults(self) -> None:
        subprocess.run(
            ["tc", "qdisc", "del", "dev", self.host_veth, "root"],
            capture_output=True,
        )

    def _set_netem(self, spec: str) -> None:
        self.clear_faults()
        _run(["tc", "qdisc", "add", "dev", self.host_veth, "root", "netem", *spec.split()])


@contextmanager
def sandbox() -> Iterator[Sandbox]:
    """Bring up a netns + veth + ICMP responder; tear it all down on exit."""
    _skip_if_unsupported()

    suffix = secrets.token_hex(3)
    netns = f"pm-{suffix}"
    host_veth = f"pmh-{suffix}"
    peer_veth = f"pmp-{suffix}"
    # /30 in 10.255.0.0/16 — high enough to avoid collisions with real nets.
    octet = secrets.randbelow(250) + 1
    host_ip = f"10.255.{octet}.1"
    target_ip = f"10.255.{octet}.2"

    responder_pid: int | None = None
    try:
        _run(["ip", "netns", "add", netns])
        _run(["ip", "link", "add", host_veth, "type", "veth", "peer", "name", peer_veth])
        _run(["ip", "link", "set", peer_veth, "netns", netns])
        _run(["ip", "addr", "add", f"{host_ip}/30", "dev", host_veth])
        _run(["ip", "link", "set", host_veth, "up"])
        _run(["ip", "netns", "exec", netns, "ip", "addr", "add", f"{target_ip}/30", "dev", peer_veth])
        _run(["ip", "netns", "exec", netns, "ip", "link", "set", peer_veth, "up"])
        _run(["ip", "netns", "exec", netns, "ip", "link", "set", "lo", "up"])

        responder_path = Path(__file__).parent / "responder.py"
        proc = subprocess.Popen(
            ["ip", "netns", "exec", netns, sys.executable, str(responder_path)],
        )
        responder_pid = proc.pid

        # Wait for responder to come up (raw socket bind is ~instant; one ping confirms).
        _wait_for_responder(target_ip, timeout=2.0)

        yield Sandbox(
            netns=netns,
            host_veth=host_veth,
            peer_veth=peer_veth,
            host_ip=host_ip,
            target_ip=target_ip,
            responder_pid=responder_pid,
        )
    finally:
        if responder_pid is not None:
            try:
                os.kill(responder_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        subprocess.run(["ip", "link", "del", host_veth], capture_output=True)
        subprocess.run(["ip", "netns", "del", netns], capture_output=True)


def _wait_for_responder(target_ip: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", target_ip],
            capture_output=True,
        )
        if result.returncode == 0:
            return
        time.sleep(0.1)
    raise RuntimeError(f"responder did not come up at {target_ip} within {timeout}s")
