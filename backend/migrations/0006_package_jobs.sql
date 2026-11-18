-- package update jobs run by the optional root helper (tsmonitor updater)
CREATE TABLE package_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    op TEXT NOT NULL,
    packages TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,          -- running | succeeded | failed | unknown
    exit_code INTEGER,
    log TEXT NOT NULL DEFAULT '',
    started_at INTEGER NOT NULL,
    finished_at INTEGER
);
