-- Dashboard accounts, browser sessions and API tokens. Secrets are never stored in clear:
-- passwords as argon2id PHC strings, session and API tokens as sha256 hex.
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    password_changed_at INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,            -- sha256 hex of the cookie value
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    sudo_until INTEGER NOT NULL DEFAULT 0,
    remote TEXT,
    user_agent TEXT
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,           -- first characters, to recognise a token in the list
    scope TEXT NOT NULL,            -- read | ops
    created_by INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    last_used_at INTEGER,
    revoked_at INTEGER
);

-- who did it: an account name, "token:<name>" or "legacy-token"
ALTER TABLE audit_log ADD COLUMN actor TEXT;
ALTER TABLE ops_jobs ADD COLUMN actor TEXT;
