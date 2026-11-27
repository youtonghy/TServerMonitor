-- changes asked for by an agent (built-in or MCP); see approvals.rs
CREATE TABLE change_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,           -- catalog name, e.g. docker.container or alert.ack
    summary TEXT NOT NULL,
    args TEXT NOT NULL,             -- exact arguments that run on approval
    reason TEXT NOT NULL,           -- why the requester wants it
    source TEXT NOT NULL,           -- agent | mcp
    actor TEXT,                     -- token name, or the conversation for the built-in agent
    remote TEXT,
    conversation_id TEXT,
    run_id TEXT,
    mode TEXT NOT NULL,             -- approve | auto (policy at request time)
    status TEXT NOT NULL,           -- pending | approved | rejected | expired | executed | failed
    preview TEXT,                   -- dry-run plan / diff (JSON)
    result TEXT,
    error TEXT,
    job_id INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    decided_at INTEGER,
    decided_by TEXT,
    note TEXT,
    finished_at INTEGER
);
CREATE INDEX change_requests_status ON change_requests (status, created_at);
CREATE INDEX change_requests_conversation ON change_requests (conversation_id);

-- per-action override of the built-in default (approve | auto)
CREATE TABLE approval_policy (
    action TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT
);
