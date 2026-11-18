-- model providers added from the dashboard; TOML [ai.profiles.*] stay read-only alongside
CREATE TABLE providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_format TEXT NOT NULL,
    base_url TEXT NOT NULL,
    auth TEXT NOT NULL DEFAULT 'api_key',
    default_model TEXT NOT NULL DEFAULT '',
    -- base64(nonce || XChaCha20-Poly1305 ciphertext); NULL = no key stored
    key_cipher TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- task kind -> provider (DB id or TOML profile name), model and reasoning effort
CREATE TABLE task_routes (
    kind TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    effort TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);
