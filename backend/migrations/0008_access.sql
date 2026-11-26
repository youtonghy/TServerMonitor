-- per-minute access log rollups (nginx_access sources), so history survives restarts
CREATE TABLE access_minutes (
    minute INTEGER PRIMARY KEY,
    requests INTEGER NOT NULL,
    s2xx INTEGER NOT NULL,
    s3xx INTEGER NOT NULL,
    s4xx INTEGER NOT NULL,
    s5xx INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    p95_ms REAL,
    detail TEXT NOT NULL            -- MinuteSummary JSON (top paths, ips, hosts, ua, histogram)
);
