from __future__ import annotations

import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass

log = logging.getLogger("supervisor")


@dataclass
class Service:
    name: str
    cmd: list[str]
    restart_backoff_s: float = 1.0
    max_backoff_s: float = 30.0


class Supervisor:
    """Minimal process supervisor: spawns child services, restarts on crash
    with exponential backoff, propagates signals."""

    def __init__(self, services: list[Service]):
        self._services = services
        self._procs: dict[str, subprocess.Popen] = {}
        self._backoff: dict[str, float] = {s.name: s.restart_backoff_s for s in services}
        self._stop = False

    def run(self) -> int:
        signal.signal(signal.SIGINT,  self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)

        for svc in self._services:
            self._spawn(svc)

        while not self._stop:
            for svc in self._services:
                p = self._procs.get(svc.name)
                if p is None:
                    continue
                rc = p.poll()
                if rc is None:
                    continue
                log.warning("%s exited rc=%s; restarting in %.1fs",
                            svc.name, rc, self._backoff[svc.name])
                time.sleep(self._backoff[svc.name])
                self._backoff[svc.name] = min(self._backoff[svc.name] * 2, svc.max_backoff_s)
                self._spawn(svc)
            time.sleep(0.5)

        self._shutdown()
        return 0

    def _spawn(self, svc: Service) -> None:
        log.info("starting %s: %s", svc.name, " ".join(svc.cmd))
        self._procs[svc.name] = subprocess.Popen(svc.cmd, start_new_session=True)
        # Reset backoff on a clean (re)start; double on next failure.
        self._backoff[svc.name] = svc.restart_backoff_s

    def _on_signal(self, _sig, _frm) -> None:
        self._stop = True

    def _shutdown(self) -> None:
        for name, p in self._procs.items():
            if p.poll() is not None:
                continue
            log.info("stopping %s", name)
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
        deadline = time.time() + 5.0
        for p in self._procs.values():
            remaining = max(0.0, deadline - time.time())
            try:
                p.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
