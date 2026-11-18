-- acknowledged alerts are not re-notified on cooldown (only on escalation);
-- silenced alerts (and new alerts with the same fingerprint) are not notified until the time passes
ALTER TABLE alerts ADD COLUMN acked_at INTEGER;
ALTER TABLE alerts ADD COLUMN silenced_until INTEGER;
CREATE INDEX alerts_fp_created ON alerts (fingerprint, created_at);

-- notification channels configured from the dashboard; [notify.*] in config.toml stay read-only
CREATE TABLE notify_channels (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,              -- telegram | email | webhook
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    min_severity TEXT NOT NULL DEFAULT 'critical',
    -- JSON list of "alert" | "report" | "digest"
    events TEXT NOT NULL,
    -- non-secret JSON settings per kind
    config TEXT NOT NULL,
    -- bot token / SMTP password / webhook HMAC secret, encrypted like provider keys
    secret_cipher TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
