from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
from pathlib import Path

from . import config as cfgmod
from .supervisor import Service, Supervisor

log = logging.getLogger("orchestrator")

REPO_ROOT  = Path(__file__).resolve().parent.parent
SCHEMA_SQL = REPO_ROOT / "sql" / "schema.sql"


def cmd_run(args: argparse.Namespace) -> int:
    cfg = cfgmod.load_yaml(args.config)
    db_path = Path(cfg["database"]["path"])
    if not db_path.exists():
        print(f"database missing: {db_path} (run `init-db` first)", file=sys.stderr)
        return 1

    conn = sqlite3.connect(db_path)
    cfgmod.upsert_targets(conn, cfg["targets"])
    conn.commit()
    conn.close()

    services = [
        Service(name="prober",   cmd=[sys.executable, "-m", "prober",   "--config", args.config]),
        Service(name="analyzer", cmd=[sys.executable, "-m", "analyzer", "--config", args.config]),
    ]
    return Supervisor(services).run()


def cmd_init_db(args: argparse.Namespace) -> int:
    cfg = cfgmod.load_yaml(args.config)
    db_path = Path(cfg["database"]["path"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL.read_text())
    conn.commit()
    conn.close()
    print(f"initialized {db_path}")
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="path-monitor")
    p.add_argument("--log-level", default="INFO")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="Run prober + analyzer under supervision")
    pr.add_argument("--config", required=True)
    pr.set_defaults(func=cmd_run)

    pi = sub.add_parser("init-db", help="Apply schema to database and seed targets")
    pi.add_argument("--config", required=True)
    pi.set_defaults(func=cmd_init_db)

    args = p.parse_args()
    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    sys.exit(args.func(args))
