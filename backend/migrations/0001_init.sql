-- res = 0 for raw samples, 300 for 5-minute rollups
CREATE TABLE metric_samples (
    ts INTEGER NOT NULL,
    res INTEGER NOT NULL DEFAULT 0,
    cpu_pct REAL NOT NULL,
    mem_pct REAL NOT NULL,
    swap_pct REAL NOT NULL,
    disk_pct REAL NOT NULL,
    load1 REAL NOT NULL,
    disk_read_bps REAL NOT NULL,
    disk_write_bps REAL NOT NULL,
    net_rx_bps REAL NOT NULL,
    net_tx_bps REAL NOT NULL,
    PRIMARY KEY (res, ts)
) WITHOUT ROWID;

CREATE TABLE container_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    container_id TEXT NOT NULL,
    name TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX container_events_ts ON container_events (ts);

-- per-minute line and error counts per log source
CREATE TABLE log_rates (
    minute INTEGER NOT NULL,
    source TEXT NOT NULL,
    lines INTEGER NOT NULL,
    errors INTEGER NOT NULL,
    PRIMARY KEY (source, minute)
) WITHOUT ROWID;
CREATE INDEX log_rates_minute ON log_rates (minute);

CREATE TABLE log_clusters (
    fingerprint TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    level TEXT NOT NULL,
    template TEXT NOT NULL,
    sample TEXT NOT NULL,
    count INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX log_clusters_last_seen ON log_clusters (last_seen);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    suggestion TEXT,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open',
    notified INTEGER NOT NULL DEFAULT 0,
    notified_at INTEGER
);
CREATE INDEX alerts_fp_status ON alerts (fingerprint, status);
CREATE INDEX alerts_created ON alerts (created_at);

CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    health_score REAL NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    generated_by TEXT NOT NULL,
    model TEXT,
    run_id TEXT,
    body TEXT NOT NULL
);
CREATE INDEX reports_kind_created ON reports (kind, created_at);

CREATE TABLE agent_runs (
    id TEXT PRIMARY KEY,
    trigger TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    model TEXT,
    steps_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    report_id INTEGER
);
CREATE INDEX agent_runs_started ON agent_runs (started_at);

CREATE TABLE agent_steps (
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    tool TEXT,
    input TEXT,
    output TEXT,
    text TEXT,
    PRIMARY KEY (run_id, seq)
) WITHOUT ROWID;

CREATE TABLE notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    channel TEXT NOT NULL,
    event TEXT NOT NULL,
    ok INTEGER NOT NULL,
    error TEXT
);

-- key/value scratch for scheduler bookkeeping (last daily report date, ...)
CREATE TABLE kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- daily totals per source (local date), kept for the yearly error heatmap
CREATE TABLE log_daily (
    date TEXT NOT NULL,
    source TEXT NOT NULL,
    lines INTEGER NOT NULL,
    errors INTEGER NOT NULL,
    PRIMARY KEY (source, date)
) WITHOUT ROWID;
