from __future__ import annotations

import argparse
import logging
import signal
import time
from contextlib import closing
from dataclasses import asdict
from pathlib import Path

import yaml

from . import db
from .detectors import Alert, LossDetector, PathChangeDetector, RttDetector
from .sinks import build_sinks

log = logging.getLogger("analyzer")


class TargetState:
    def __init__(self, target_id: int, cfg: dict):
        self.target_id = target_id
        self.rtt  = RttDetector(window=cfg["rtt"]["window"],
                                 z_threshold=cfg["rtt"]["z_score_threshold"])
        self.loss = LossDetector(window=cfg["loss"]["window"],
                                  threshold=cfg["loss"]["threshold"])
        self.path = PathChangeDetector()
        self.last_seen_probe_ts: int = 0


def run(config_path: str) -> None:
    cfg = yaml.safe_load(Path(config_path).read_text())
    db_path = cfg["database"]["path"]
    poll_s  = cfg["analyzer"]["poll_interval_s"]

    with closing(db.connect(db_path)) as conn:
        sinks = build_sinks(cfg["alerts"]["sinks"])

        targets = db.list_targets(conn)
        state = {t["id"]: TargetState(t["id"], cfg["analyzer"]) for t in targets}

        stop = False
        def handle(_sig, _frm):
            nonlocal stop
            stop = True
        signal.signal(signal.SIGINT, handle)
        signal.signal(signal.SIGTERM, handle)

        log.info("analyzer running over %d targets", len(state))
        while not stop:
            for tid, st in state.items():
                rows = db.fetch_recent_probes(conn, tid, st.last_seen_probe_ts)
                for r in rows:
                    if r["timestamp"] <= st.last_seen_probe_ts:
                        continue
                    st.last_seen_probe_ts = r["timestamp"]
                    alerts: list[Alert] = []
                    if r["status"] == "ok":
                        a = st.rtt.observe(tid, r["timestamp"], r["rtt_us"])
                        if a: alerts.append(a)
                    a = st.loss.observe(tid, r["timestamp"], r["status"])
                    if a: alerts.append(a)

                    latest_hash = db.fetch_latest_path_hash(conn, tid)
                    a = st.path.observe(tid, r["timestamp"], latest_hash)
                    if a: alerts.append(a)

                    for al in alerts:
                        db.insert_alert(conn, al.target_id, al.timestamp_us, al.type, al.details)
                        for s in sinks:
                            s.emit(al)
            time.sleep(poll_s)

        for s in sinks:
            s.close()


def main() -> None:
    p = argparse.ArgumentParser(prog="analyzer")
    p.add_argument("--config", required=True)
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()
    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    run(args.config)
