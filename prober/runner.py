"""Probe scheduler: dispatches per-target probes and traceroutes on a thread pool."""
from __future__ import annotations

import argparse
import logging
import random
import signal
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from itertools import count
from pathlib import Path

import yaml

from .db_writer import DbWriter, PathRecord, ProbeRecord
from .icmp_socket import IcmpSocket
from .traceroute import run_traceroute

log = logging.getLogger("prober")


@dataclass
class Target:
    id: int
    hostname: str
    ip: str


def _probe_once(target: Target, identifier: int, sequence: int,
                timeout_s: float, writer: DbWriter) -> None:
    try:
        with IcmpSocket() as sock:
            if not sock.send_echo(target.ip, identifier, sequence, ttl=64):
                writer.enqueue(ProbeRecord(target.id, time.time_ns() // 1000, None, "sendfail"))
                return
            reply = sock.recv_reply(identifier, timeout_s)
    except OSError as e:
        log.warning("socket error for %s: %s", target.ip, e)
        writer.enqueue(ProbeRecord(target.id, time.time_ns() // 1000, None, "sendfail"))
        return

    if reply.received and reply.sequence == sequence:
        writer.enqueue(ProbeRecord(target.id, time.time_ns() // 1000, reply.rtt_us, "ok"))
    elif reply.received:
        writer.enqueue(ProbeRecord(target.id, time.time_ns() // 1000, None, "unreachable"))
    else:
        writer.enqueue(ProbeRecord(target.id, time.time_ns() // 1000, None, "timeout"))


def _trace_once(target: Target, identifier: int, max_hops: int,
                timeout_s: float, writer: DbWriter) -> None:
    try:
        with IcmpSocket() as sock:
            tr = run_traceroute(sock, target.ip, identifier, max_hops, timeout_s)
    except OSError as e:
        log.warning("traceroute socket error for %s: %s", target.ip, e)
        return
    writer.enqueue(PathRecord(target.id, time.time_ns() // 1000, tr))


def run(config_path: str) -> int:
    cfg = yaml.safe_load(Path(config_path).read_text())
    db_path = cfg["database"]["path"]
    pcfg    = cfg["prober"]
    tcfg    = pcfg["traceroute"]

    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT id, hostname, ip FROM targets").fetchall()
    conn.close()
    targets = [Target(id=r[0], hostname=r[1], ip=r[2]) for r in rows]
    if not targets:
        log.error("no targets in DB; run `orchestrator init-db` and start orchestrator")
        return 1

    # Per-target ICMP identifier (16-bit) chosen at startup; sequence counters
    # increment per probe. Identifiers separate concurrent probes' reply streams.
    identifiers  = {t.id: random.randint(1, 0xFFFF) for t in targets}
    seq_counters = {t.id: count(1) for t in targets}

    writer = DbWriter(db_path)
    pool   = ThreadPoolExecutor(max_workers=pcfg["worker_threads"])

    stop = threading.Event()
    signal.signal(signal.SIGINT,  lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    probe_interval_s = pcfg["probe_interval_ms"] / 1000.0
    probe_timeout_s  = pcfg["probe_timeout_ms"]  / 1000.0
    next_probe       = time.monotonic()
    next_trace       = time.monotonic() + tcfg["interval_s"]

    log.info(f"prober running: {len(targets)} targets, interval={probe_interval_s:.2f}s")
    try:
        while not stop.is_set():
            now = time.monotonic()
            if now >= next_probe:
                for t in targets:
                    seq = next(seq_counters[t.id]) & 0xFFFF
                    pool.submit(_probe_once, t, identifiers[t.id], seq,
                                probe_timeout_s, writer)
                next_probe += probe_interval_s

            if tcfg["enabled"] and now >= next_trace:
                for t in targets:
                    pool.submit(_trace_once, t, identifiers[t.id],
                                tcfg["max_hops"], probe_timeout_s, writer)
                next_trace += tcfg["interval_s"]

            next_wake = next_probe
            if tcfg["enabled"]:
                next_wake = min(next_wake, next_trace)
            stop.wait(max(0, next_wake - time.monotonic()))
    finally:
        pool.shutdown(wait=True)
        writer.stop()
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="prober")
    p.add_argument("--config", required=True)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()
    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    raise SystemExit(run(args.config))
