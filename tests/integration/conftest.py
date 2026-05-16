"""Pytest fixtures for integration tests.

Each test gets a fresh netns sandbox, a temp DB, a temp config pointing at the
sandbox target, an initialized DB, and a running path-monitor subprocess. All
teardown is wired into the fixture finalizers — no orphaned state on crash.
"""
from __future__ import annotations

import os
import signal
import sqlite3
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from .netns import Sandbox, sandbox


@dataclass
class Harness:
    sandbox: Sandbox
    db_path: Path
    config_path: Path

    def conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def alerts_of_type(self, alert_type: str) -> list[tuple]:
        with self.conn() as c:
            return c.execute(
                "SELECT id, target_id, timestamp, type, details FROM alerts WHERE type = ?",
                (alert_type,),
            ).fetchall()

    def all_alerts(self) -> list[tuple]:
        with self.conn() as c:
            return c.execute(
                "SELECT id, target_id, timestamp, type, details FROM alerts"
            ).fetchall()

    def wait_for_alert(self, alert_type: str, timeout_s: float) -> tuple | None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            alerts = self.alerts_of_type(alert_type)
            if alerts:
                return alerts[0]
            time.sleep(0.5)
        return None


def _write_config(path: Path, db_path: Path, target_ip: str,
                  loss_window: int, rtt_window: int) -> None:
    path.write_text(textwrap.dedent(f"""\
        database:
          path: {db_path}

        prober:
          probe_interval_ms: 200
          probe_timeout_ms: 1000
          worker_threads: 2
          traceroute:
            enabled: false
            mode: icmp
            max_hops: 5
            interval_s: 9999

        analyzer:
          poll_interval_s: 1
          rtt:
            window: {rtt_window}
            z_score_threshold: 3.0
          loss:
            window: {loss_window}
            threshold: 0.20
          path_change:
            enabled: false

        alerts:
          sinks:
            - type: stdout

        targets:
          - hostname: target
            ip: {target_ip}
        """))


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[Harness]:
    """Bring up sandbox + DB + config + path-monitor; tear it all down on exit."""
    with sandbox() as sb:
        db_path = tmp_path / "test.db"
        config_path = tmp_path / "config.yaml"
        _write_config(
            config_path,
            db_path=db_path,
            target_ip=sb.target_ip,
            loss_window=15,
            rtt_window=20,
        )

        repo_root = Path(__file__).resolve().parents[2]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root)

        subprocess.run(
            [sys.executable, "-m", "orchestrator", "init-db", "--config", str(config_path)],
            check=True,
            env=env,
            cwd=repo_root,
        )

        proc = subprocess.Popen(
            [sys.executable, "-m", "orchestrator", "run", "--config", str(config_path)],
            env=env,
            cwd=repo_root,
        )
        try:
            yield Harness(sandbox=sb, db_path=db_path, config_path=config_path)
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
