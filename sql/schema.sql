PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS targets (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    ip       TEXT NOT NULL,
    UNIQUE (hostname, ip)
);

CREATE TABLE IF NOT EXISTS probes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    timestamp INTEGER NOT NULL,
    rtt_us    INTEGER,
    status    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_probes_target_ts ON probes(target_id, timestamp);

CREATE TABLE IF NOT EXISTS paths (
    probe_id   INTEGER NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
    hop_num    INTEGER NOT NULL,
    hop_ip     TEXT,
    hop_rtt_us INTEGER,
    path_hash  TEXT,
    PRIMARY KEY (probe_id, hop_num)
);

CREATE INDEX IF NOT EXISTS idx_paths_hash ON paths(path_hash);

CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    timestamp INTEGER NOT NULL,
    type      TEXT NOT NULL,
    details   TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_target_ts ON alerts(target_id, timestamp);
