-- user prompts; built-in prompts ship in code (agent/library.rs) and are read-only
CREATE TABLE prompts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- automated agent tasks beyond the fixed [schedule] jobs
CREATE TABLE scheduled_tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    -- JSON trigger: {"type":"interval","every_mins":N} | {"type":"daily","at":"HH:MM"}
    -- | {"type":"log_threshold","source":null,"metric":"errors","count":N,"min_interval_mins":N}
    -- | {"type":"burst"} | {"type":"manual"}
    trigger TEXT NOT NULL,
    prompt_id TEXT NOT NULL,
    -- task routing kind (settings TASK_KINDS) used to pick the model
    route_kind TEXT NOT NULL DEFAULT 'default',
    last_fired_at INTEGER,
    -- log threshold counting starts here (ms)
    cursor INTEGER,
    last_run_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- built-in tasks: the daily local security check (on) and a periodic log scan (off)
INSERT INTO scheduled_tasks (id, name, enabled, builtin, trigger, prompt_id, route_kind, cursor, created_at, updated_at)
VALUES
    ('t_security_check', '每日本机安全体检', 1, 1, '{"type":"daily","at":"03:30"}', 'builtin:security_check', 'security_check',
     CAST(strftime('%s','now') AS INTEGER) * 1000, CAST(strftime('%s','now') AS INTEGER) * 1000, CAST(strftime('%s','now') AS INTEGER) * 1000),
    ('t_log_scan', '日志定时扫描', 0, 1, '{"type":"interval","every_mins":360}', 'builtin:log_scan', 'log_scan',
     CAST(strftime('%s','now') AS INTEGER) * 1000, CAST(strftime('%s','now') AS INTEGER) * 1000, CAST(strftime('%s','now') AS INTEGER) * 1000);
