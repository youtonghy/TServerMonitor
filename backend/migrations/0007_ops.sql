-- changes executed through the optional root ops helper (tsmonitor helper)
CREATE TABLE ops_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,           -- docker | nginx | firewall | ssh | pending
    call TEXT NOT NULL,             -- helper call, e.g. docker.container
    summary TEXT NOT NULL,
    args TEXT NOT NULL DEFAULT '{}',-- redacted (file contents replaced by size + hash)
    dry_run INTEGER NOT NULL DEFAULT 0,
    via TEXT NOT NULL,              -- web | mcp
    remote TEXT,
    status TEXT NOT NULL,           -- running | succeeded | failed | unknown
    error TEXT,
    result TEXT,
    log TEXT NOT NULL DEFAULT '',
    started_at INTEGER NOT NULL,
    finished_at INTEGER
);
CREATE INDEX ops_jobs_started ON ops_jobs (started_at);

-- who asked for what; one row per write request, including refused ones
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    via TEXT NOT NULL,
    remote TEXT,
    call TEXT NOT NULL,
    summary TEXT NOT NULL,
    dry_run INTEGER NOT NULL DEFAULT 0,
    outcome TEXT NOT NULL,          -- started | succeeded | failed | refused
    detail TEXT,
    job_id INTEGER
);
CREATE INDEX audit_log_ts ON audit_log (ts);
