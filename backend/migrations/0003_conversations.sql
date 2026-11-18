-- every agent run belongs to a conversation: scheduled runs get one each, chats hold many turns
CREATE TABLE conversations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    -- "chat" for user conversations, otherwise the task kind of the run that created it
    kind TEXT NOT NULL,
    -- optional JSON {report_id | alert_id | run_id} the conversation is about
    context TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX conversations_updated ON conversations (updated_at);

ALTER TABLE agent_runs ADD COLUMN conversation_id TEXT;
CREATE INDEX agent_runs_conversation ON agent_runs (conversation_id, started_at);

-- backfill: one conversation per existing run
INSERT INTO conversations (id, title, kind, created_at, updated_at)
SELECT
    'c_' || id,
    CASE kind
        WHEN 'hourly' THEN '小时巡检'
        WHEN 'daily' THEN '每日运维简报'
        WHEN 'incident' THEN '异常事件分析'
        WHEN 'audit' THEN '深度审计'
        ELSE kind
    END || ' · ' || strftime('%Y-%m-%d %H:%M', started_at / 1000, 'unixepoch', 'localtime'),
    kind,
    started_at,
    COALESCE(finished_at, started_at)
FROM agent_runs;
UPDATE agent_runs SET conversation_id = 'c_' || id;
