from __future__ import annotations

import json
import socket
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from .detectors import Alert


class AlertSink(Protocol):
    def emit(self, alert: Alert) -> None: ...
    def close(self) -> None: ...


class StdoutSink:
    def emit(self, alert: Alert) -> None:
        sys.stdout.write(json.dumps(asdict(alert)) + "\n")
        sys.stdout.flush()

    def close(self) -> None:
        pass


class FileSink:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a", buffering=1)

    def emit(self, alert: Alert) -> None:
        self._fh.write(json.dumps(asdict(alert)) + "\n")

    def close(self) -> None:
        self._fh.close()


class TcpSink:
    def __init__(self, host: str, port: int):
        self._addr = (host, port)
        self._sock: socket.socket | None = None

    def _ensure(self) -> socket.socket:
        if self._sock is None:
            s = socket.create_connection(self._addr, timeout=2.0)
            self._sock = s
        return self._sock

    def emit(self, alert: Alert) -> None:
        line = (json.dumps(asdict(alert)) + "\n").encode()
        try:
            self._ensure().sendall(line)
        except OSError:
            if self._sock:
                self._sock.close()
            self._sock = None

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None


def build_sinks(specs: list[dict]) -> list[AlertSink]:
    sinks: list[AlertSink] = []
    for s in specs:
        kind = s.get("type")
        if kind == "stdout":
            sinks.append(StdoutSink())
        elif kind == "file":
            sinks.append(FileSink(s["path"]))
        elif kind == "tcp":
            sinks.append(TcpSink(s["host"], int(s["port"])))
        else:
            raise ValueError(f"unknown sink type: {kind}")
    return sinks
