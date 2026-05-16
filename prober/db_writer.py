"""Background SQLite writer: serializes probe and path inserts on a single thread."""
from __future__ import annotations

import queue
import sqlite3
import threading
from dataclasses import dataclass

from .traceroute import TracerouteResult


@dataclass
class ProbeRecord:
    target_id: int
    timestamp_us: int
    rtt_us: int | None  # None on timeout / sendfail
    status: str         # "ok" | "timeout" | "unreachable" | "sendfail"


@dataclass
class PathRecord:
    target_id: int
    timestamp_us: int
    trace: TracerouteResult


class DbWriter:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._q: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def enqueue(self, record: ProbeRecord | PathRecord) -> None:
        self._q.put(record)

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)  # wake the loop
        self._thread.join()

    def _run(self) -> None:
        conn = sqlite3.connect(self._db_path, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            while True:
                item = self._q.get()
                if item is None:
                    if self._stop.is_set() and self._q.empty():
                        return
                    continue
                if isinstance(item, ProbeRecord):
                    self._write_probe(conn, item)
                else:
                    self._write_path(conn, item)
        finally:
            conn.close()

    @staticmethod
    def _write_probe(conn: sqlite3.Connection, r: ProbeRecord) -> None:
        conn.execute(
            "INSERT INTO probes(target_id, timestamp, rtt_us, status) VALUES (?, ?, ?, ?)",
            (r.target_id, r.timestamp_us, r.rtt_us, r.status),
        )

    @staticmethod
    def _write_path(conn: sqlite3.Connection, r: PathRecord) -> None:
        conn.execute("BEGIN")
        try:
            cur = conn.execute(
                "INSERT INTO probes(target_id, timestamp, rtt_us, status) "
                "VALUES (?, ?, NULL, 'trace')",
                (r.target_id, r.timestamp_us),
            )
            probe_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO paths(probe_id, hop_num, hop_ip, hop_rtt_us, path_hash) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (probe_id, h.ttl, h.ip or None,
                     h.rtt_us if h.responded else None, r.trace.path_hash)
                    for h in r.trace.hops
                ],
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
