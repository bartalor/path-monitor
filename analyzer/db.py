import sqlite3
from contextlib import contextmanager
from pathlib import Path


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection):
    conn.execute("BEGIN;")
    try:
        yield
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        raise


def fetch_recent_probes(conn, target_id: int, since_ts_us: int):
    return conn.execute(
        "SELECT id, timestamp, rtt_us, status FROM probes "
        "WHERE target_id = ? AND timestamp > ? AND status != 'trace' "
        "ORDER BY timestamp ASC",
        (target_id, since_ts_us),
    ).fetchall()


def fetch_latest_path_hash(conn, target_id: int) -> str | None:
    row = conn.execute(
        "SELECT p.path_hash "
        "FROM probes pr JOIN paths p ON p.probe_id = pr.id "
        "WHERE pr.target_id = ? AND pr.status = 'trace' "
        "ORDER BY pr.timestamp DESC LIMIT 1",
        (target_id,),
    ).fetchone()
    return row["path_hash"] if row else None


def insert_alert(conn, target_id: int, ts_us: int, alert_type: str, details: str) -> int:
    cur = conn.execute(
        "INSERT INTO alerts(target_id, timestamp, type, details) VALUES (?, ?, ?, ?)",
        (target_id, ts_us, alert_type, details),
    )
    return cur.lastrowid


def list_targets(conn):
    return conn.execute("SELECT id, hostname, ip FROM targets").fetchall()
