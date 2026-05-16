from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Target:
    id: int
    hostname: str
    ip: str


def load_yaml(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text())


def upsert_targets(conn: sqlite3.Connection, targets: list[dict]) -> list[Target]:
    out: list[Target] = []
    for t in targets:
        conn.execute(
            "INSERT OR IGNORE INTO targets(hostname, ip) VALUES (?, ?)",
            (t["hostname"], t["ip"]),
        )
        row = conn.execute(
            "SELECT id, hostname, ip FROM targets WHERE hostname=? AND ip=?",
            (t["hostname"], t["ip"]),
        ).fetchone()
        out.append(Target(id=row[0], hostname=row[1], ip=row[2]))
    return out
