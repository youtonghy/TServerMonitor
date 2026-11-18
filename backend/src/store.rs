//! SQLite persistence. All queries are runtime-checked (`sqlx::query`) to keep builds offline.

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

use crate::model::{
    AgentRun, AgentStep, Conversation, Finding, LogCluster, MetricPoint, Report, ReportSummary,
    now_ms,
};

pub type Db = SqlitePool;

pub async fn open(data_dir: &Path) -> Result<Db> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating {}", data_dir.display()))?;
    let path = data_dir.join("tsmonitor.db");
    open_at(&format!("sqlite://{}", path.display())).await
}

pub async fn open_at(url: &str) -> Result<Db> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .context("opening sqlite")?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running migrations")?;
    Ok(pool)
}

#[cfg(test)]
pub async fn open_memory() -> Db {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:").unwrap();
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}

// ---------------------------------------------------------------- metrics

pub async fn insert_metric(db: &Db, p: &MetricPoint) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO metric_samples (ts, res, cpu_pct, mem_pct, swap_pct, disk_pct, load1, disk_read_bps, disk_write_bps, net_rx_bps, net_tx_bps)
         VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(p.ts)
    .bind(p.cpu_pct)
    .bind(p.mem_pct)
    .bind(p.swap_pct)
    .bind(p.disk_pct)
    .bind(p.load1)
    .bind(p.disk_read_bps)
    .bind(p.disk_write_bps)
    .bind(p.net_rx_bps)
    .bind(p.net_tx_bps)
    .execute(db)
    .await?;
    Ok(())
}

const ROLLUP_MS: i64 = 300_000;

/// Writes 5-minute averages for every complete bucket between `from` and `to`.
pub async fn rollup_metrics(db: &Db, from: i64, to: i64) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO metric_samples (ts, res, cpu_pct, mem_pct, swap_pct, disk_pct, load1, disk_read_bps, disk_write_bps, net_rx_bps, net_tx_bps)
         SELECT (ts / ?1) * ?1 AS b, 300, avg(cpu_pct), avg(mem_pct), avg(swap_pct), avg(disk_pct), avg(load1),
                avg(disk_read_bps), avg(disk_write_bps), avg(net_rx_bps), avg(net_tx_bps)
         FROM metric_samples WHERE res = 0 AND ts >= ?2 AND ts < ?3 GROUP BY b",
    )
    .bind(ROLLUP_MS)
    .bind(from / ROLLUP_MS * ROLLUP_MS)
    .bind(to / ROLLUP_MS * ROLLUP_MS)
    .execute(db)
    .await?;
    Ok(())
}

pub fn range_ms(range: &str) -> Option<i64> {
    let h = 3_600_000;
    Some(match range {
        "1h" => h,
        "6h" => 6 * h,
        "24h" => 24 * h,
        "7d" => 7 * 24 * h,
        "30d" => 30 * 24 * h,
        _ => return None,
    })
}

/// Returns at most ~360 points for the range, averaged into equal buckets.
pub async fn query_metrics(db: &Db, span_ms: i64, now: i64) -> Result<(i64, Vec<MetricPoint>)> {
    let res = if span_ms > 24 * 3_600_000 { 300 } else { 0 };
    let step_ms = (span_ms / 360).max(if res == 0 { 10_000 } else { ROLLUP_MS });
    let rows = sqlx::query(
        "SELECT (ts / ?1) * ?1 AS b, avg(cpu_pct), avg(mem_pct), avg(swap_pct), avg(disk_pct), avg(load1),
                avg(disk_read_bps), avg(disk_write_bps), avg(net_rx_bps), avg(net_tx_bps)
         FROM metric_samples WHERE res = ?2 AND ts >= ?3 GROUP BY b ORDER BY b",
    )
    .bind(step_ms)
    .bind(res)
    .bind(now - span_ms)
    .fetch_all(db)
    .await?;
    let points = rows
        .into_iter()
        .map(|r| MetricPoint {
            ts: r.get(0),
            cpu_pct: r.get(1),
            mem_pct: r.get(2),
            swap_pct: r.get(3),
            disk_pct: r.get(4),
            load1: r.get(5),
            disk_read_bps: r.get(6),
            disk_write_bps: r.get(7),
            net_rx_bps: r.get(8),
            net_tx_bps: r.get(9),
        })
        .collect();
    Ok((step_ms / 1000, points))
}

pub async fn apply_retention(db: &Db, raw_days: i64, rollup_days: i64) -> Result<()> {
    let day = 86_400_000;
    let now = now_ms();
    sqlx::query("DELETE FROM metric_samples WHERE res = 0 AND ts < ?")
        .bind(now - raw_days * day)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM metric_samples WHERE res = 300 AND ts < ?")
        .bind(now - rollup_days * day)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM log_rates WHERE minute < ?")
        .bind(now - rollup_days.min(30) * day)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM log_clusters WHERE last_seen < ?")
        .bind(now - rollup_days * day)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM container_events WHERE ts < ?")
        .bind(now - rollup_days * day)
        .execute(db)
        .await?;
    sqlx::query(
        "DELETE FROM agent_steps WHERE run_id IN (SELECT id FROM agent_runs WHERE started_at < ?)",
    )
    .bind(now - rollup_days * day)
    .execute(db)
    .await?;
    sqlx::query("DELETE FROM agent_runs WHERE started_at < ?")
        .bind(now - rollup_days * day)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM notifications WHERE ts < ?")
        .bind(now - rollup_days * day)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM alerts WHERE status = 'resolved' AND last_seen < ?")
        .bind(now - rollup_days * day)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------- containers

pub async fn insert_container_event(
    db: &Db,
    ts: i64,
    id: &str,
    name: &str,
    action: &str,
    detail: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO container_events (ts, container_id, name, action, detail) VALUES (?, ?, ?, ?, ?)")
        .bind(ts)
        .bind(id)
        .bind(name)
        .bind(action)
        .bind(detail)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn recent_container_events(
    db: &Db,
    since: i64,
    limit: i64,
) -> Result<Vec<serde_json::Value>> {
    let rows = sqlx::query("SELECT ts, name, action, detail FROM container_events WHERE ts >= ? ORDER BY ts DESC LIMIT ?")
        .bind(since)
        .bind(limit)
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "ts": r.get::<i64, _>(0), "name": r.get::<String, _>(1),
                "action": r.get::<String, _>(2), "detail": r.get::<String, _>(3),
            })
        })
        .collect())
}

// ---------------------------------------------------------------- logs

pub struct RateRow<'a> {
    pub minute: i64,
    pub source: &'a str,
    pub lines: i64,
    pub errors: i64,
    pub date: String,
}

pub async fn add_log_rates(db: &Db, rows: &[RateRow<'_>]) -> Result<()> {
    let mut tx = db.begin().await?;
    for r in rows {
        sqlx::query(
            "INSERT INTO log_rates (minute, source, lines, errors) VALUES (?, ?, ?, ?)
             ON CONFLICT(source, minute) DO UPDATE SET lines = lines + excluded.lines, errors = errors + excluded.errors",
        )
        .bind(r.minute)
        .bind(r.source)
        .bind(r.lines)
        .bind(r.errors)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO log_daily (date, source, lines, errors) VALUES (?, ?, ?, ?)
             ON CONFLICT(source, date) DO UPDATE SET lines = lines + excluded.lines, errors = errors + excluded.errors",
        )
        .bind(&r.date)
        .bind(r.source)
        .bind(r.lines)
        .bind(r.errors)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn upsert_clusters(db: &Db, clusters: &[LogCluster]) -> Result<()> {
    let mut tx = db.begin().await?;
    for c in clusters {
        sqlx::query(
            "INSERT INTO log_clusters (fingerprint, source, level, template, sample, count, first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(fingerprint) DO UPDATE SET count = count + excluded.count, sample = excluded.sample,
                last_seen = max(last_seen, excluded.last_seen)",
        )
        .bind(&c.fingerprint)
        .bind(&c.source)
        .bind(&c.level)
        .bind(&c.template)
        .bind(&c.sample)
        .bind(c.count)
        .bind(c.first_seen)
        .bind(c.last_seen)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[derive(Default)]
pub struct ClusterQuery<'a> {
    pub source: Option<&'a str>,
    pub level: Option<&'a str>,
    pub contains: Option<&'a str>,
    pub since: Option<i64>,
    pub limit: i64,
    pub order_by_count: bool,
}

pub async fn query_clusters(db: &Db, q: &ClusterQuery<'_>) -> Result<Vec<LogCluster>> {
    let order = if q.order_by_count {
        "count DESC"
    } else {
        "last_seen DESC"
    };
    let sql = format!(
        "SELECT fingerprint, source, level, template, sample, count, first_seen, last_seen FROM log_clusters
         WHERE (?1 IS NULL OR source = ?1) AND (?2 IS NULL OR level = ?2)
           AND (?3 IS NULL OR instr(lower(template), lower(?3)) > 0) AND (?4 IS NULL OR last_seen >= ?4)
         ORDER BY {order} LIMIT ?5"
    );
    Ok(sqlx::query_as::<_, LogCluster>(sqlx::AssertSqlSafe(sql))
        .bind(q.source)
        .bind(q.level)
        .bind(q.contains)
        .bind(q.since)
        .bind(q.limit.clamp(1, 500))
        .fetch_all(db)
        .await?)
}

pub struct RateSeries {
    pub source: String,
    pub points: Vec<(i64, i64, i64)>,
}

pub async fn query_log_rates(db: &Db, span_ms: i64, now: i64) -> Result<(i64, Vec<RateSeries>)> {
    let step_ms = (span_ms / 120).max(60_000) / 60_000 * 60_000;
    let rows = sqlx::query(
        "SELECT source, (minute / ?1) * ?1 AS b, sum(lines), sum(errors) FROM log_rates
         WHERE minute >= ?2 GROUP BY source, b ORDER BY source, b",
    )
    .bind(step_ms)
    .bind(now - span_ms)
    .fetch_all(db)
    .await?;
    let mut out: Vec<RateSeries> = Vec::new();
    for r in rows {
        let source: String = r.get(0);
        let point = (r.get::<i64, _>(1), r.get::<i64, _>(2), r.get::<i64, _>(3));
        match out.last_mut() {
            Some(s) if s.source == source => s.points.push(point),
            _ => out.push(RateSeries {
                source,
                points: vec![point],
            }),
        }
    }
    Ok((step_ms / 1000, out))
}

pub async fn daily_errors(db: &Db, days: i64) -> Result<Vec<(String, i64)>> {
    let since = (chrono::Local::now() - chrono::Duration::days(days))
        .format("%Y-%m-%d")
        .to_string();
    let rows = sqlx::query(
        "SELECT date, sum(errors) FROM log_daily WHERE date > ? GROUP BY date ORDER BY date",
    )
    .bind(since)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.get(0), r.get(1))).collect())
}

// ---------------------------------------------------------------- findings

pub struct NewFinding<'a> {
    pub key: &'a str,
    pub category: &'a str,
    pub severity: &'a str,
    pub title: &'a str,
    pub detail: &'a str,
    pub evidence: &'a str,
}

/// Inserts or refreshes a finding. Returns true when it is new (or re-opened).
pub async fn upsert_finding(db: &Db, f: &NewFinding<'_>) -> Result<bool> {
    let now = now_ms();
    let existing: Option<(i64, bool)> =
        sqlx::query_as("SELECT id, resolved FROM findings WHERE key = ?")
            .bind(f.key)
            .fetch_optional(db)
            .await?;
    sqlx::query(
        "INSERT INTO findings (key, category, severity, title, detail, evidence, first_seen, last_seen, resolved)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 0)
         ON CONFLICT(key) DO UPDATE SET severity = excluded.severity, title = excluded.title, detail = excluded.detail,
            evidence = excluded.evidence, last_seen = excluded.last_seen, resolved = 0",
    )
    .bind(f.key)
    .bind(f.category)
    .bind(f.severity)
    .bind(f.title)
    .bind(f.detail)
    .bind(f.evidence)
    .bind(now)
    .execute(db)
    .await?;
    Ok(!matches!(existing, Some((_, false))))
}

/// Marks findings of a category resolved unless their key is in `keep`.
pub async fn resolve_findings_except(db: &Db, category: &str, keep: &[String]) -> Result<()> {
    let keys = serde_json::to_string(keep)?;
    sqlx::query(
        "UPDATE findings SET resolved = 1 WHERE category = ? AND resolved = 0 AND key NOT IN (SELECT value FROM json_each(?))",
    )
    .bind(category)
    .bind(keys)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_findings(db: &Db, include_resolved: bool) -> Result<Vec<Finding>> {
    Ok(sqlx::query_as::<_, Finding>(
        "SELECT id, category, severity, title, detail, evidence, first_seen, last_seen, resolved FROM findings
         WHERE ? OR resolved = 0
         ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC",
    )
    .bind(include_resolved)
    .fetch_all(db)
    .await?)
}

// ---------------------------------------------------------------- reports

const REPORT_COLS: &str =
    "id, kind, created_at, health_score, title, summary, generated_by, model, run_id";

pub struct NewReport<'a> {
    pub kind: &'a str,
    pub health_score: f64,
    pub title: &'a str,
    pub summary: &'a str,
    pub generated_by: &'a str,
    pub model: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub body: &'a serde_json::Value,
}

pub async fn insert_report(db: &Db, r: &NewReport<'_>) -> Result<ReportSummary> {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO reports (kind, created_at, health_score, title, summary, generated_by, model, run_id, body)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(r.kind)
    .bind(now_ms())
    .bind(r.health_score)
    .bind(r.title)
    .bind(r.summary)
    .bind(r.generated_by)
    .bind(r.model)
    .bind(r.run_id)
    .bind(serde_json::to_string(r.body)?)
    .fetch_one(db)
    .await?;
    let sql = format!("SELECT {REPORT_COLS} FROM reports WHERE id = ?");
    Ok(sqlx::query_as::<_, ReportSummary>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_one(db)
        .await?)
}

pub async fn list_reports(db: &Db, kind: Option<&str>, limit: i64) -> Result<Vec<ReportSummary>> {
    let sql = format!(
        "SELECT {REPORT_COLS} FROM reports WHERE (?1 IS NULL OR kind = ?1) ORDER BY created_at DESC, id DESC LIMIT ?2"
    );
    Ok(sqlx::query_as::<_, ReportSummary>(sqlx::AssertSqlSafe(sql))
        .bind(kind)
        .bind(limit.clamp(1, 500))
        .fetch_all(db)
        .await?)
}

pub async fn get_report(db: &Db, id: Option<i64>, kind: Option<&str>) -> Result<Option<Report>> {
    let sql = format!(
        "SELECT {REPORT_COLS}, body FROM reports WHERE (?1 IS NULL OR id = ?1) AND (?2 IS NULL OR kind = ?2)
         ORDER BY created_at DESC, id DESC LIMIT 1"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .bind(kind)
        .fetch_optional(db)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let summary = ReportSummary {
        id: row.get(0),
        kind: row.get(1),
        created_at: row.get(2),
        health_score: row.get(3),
        title: row.get(4),
        summary: row.get(5),
        generated_by: row.get(6),
        model: row.get(7),
        run_id: row.get(8),
    };
    let body: String = row.get(9);
    Ok(Some(Report {
        summary,
        body: serde_json::from_str(&body)?,
    }))
}

// ---------------------------------------------------------------- agent runs

pub struct NewRun<'a> {
    pub id: &'a str,
    pub trigger: &'a str,
    pub kind: &'a str,
    pub model: Option<&'a str>,
    pub conversation_id: &'a str,
}

pub async fn insert_run(db: &Db, r: &NewRun<'_>) -> Result<()> {
    let now = now_ms();
    sqlx::query("INSERT INTO agent_runs (id, trigger, kind, status, started_at, model, conversation_id) VALUES (?, ?, ?, 'running', ?, ?, ?)")
        .bind(r.id)
        .bind(r.trigger)
        .bind(r.kind)
        .bind(now)
        .bind(r.model)
        .bind(r.conversation_id)
        .execute(db)
        .await?;
    sqlx::query("UPDATE conversations SET updated_at = ? WHERE id = ?")
        .bind(now)
        .bind(r.conversation_id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn finish_run(
    db: &Db,
    id: &str,
    status: &str,
    error: Option<&str>,
    report_id: Option<i64>,
) -> Result<()> {
    sqlx::query(
        "UPDATE agent_runs SET status = ?, finished_at = ?, error = ?, report_id = ? WHERE id = ?",
    )
    .bind(status)
    .bind(now_ms())
    .bind(error)
    .bind(report_id)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

/// Runs left in "running" by a crash are closed on startup.
pub async fn close_stale_runs(db: &Db) -> Result<()> {
    sqlx::query("UPDATE agent_runs SET status = 'failed', finished_at = ?, error = 'daemon restarted' WHERE status = 'running'")
        .bind(now_ms())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn insert_step(db: &Db, run_id: &str, step: &AgentStep) -> Result<()> {
    let enc = |v: &Option<serde_json::Value>| v.as_ref().map(|v| v.to_string());
    sqlx::query("INSERT INTO agent_steps (run_id, seq, ts, kind, tool, input, output, text) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(run_id)
        .bind(step.seq)
        .bind(step.ts)
        .bind(&step.kind)
        .bind(&step.tool)
        .bind(enc(&step.input))
        .bind(enc(&step.output))
        .bind(&step.text)
        .execute(db)
        .await?;
    sqlx::query("UPDATE agent_runs SET steps_count = steps_count + 1 WHERE id = ?")
        .bind(run_id)
        .execute(db)
        .await?;
    Ok(())
}

const RUN_COLS: &str = "id, trigger, kind, status, started_at, finished_at, model, steps_count, error, report_id, conversation_id";

pub async fn list_runs(db: &Db, limit: i64) -> Result<Vec<AgentRun>> {
    let sql = format!("SELECT {RUN_COLS} FROM agent_runs ORDER BY started_at DESC LIMIT ?");
    Ok(sqlx::query_as::<_, AgentRun>(sqlx::AssertSqlSafe(sql))
        .bind(limit.clamp(1, 500))
        .fetch_all(db)
        .await?)
}

pub async fn get_run(db: &Db, id: &str) -> Result<Option<(AgentRun, Vec<AgentStep>)>> {
    let sql = format!("SELECT {RUN_COLS} FROM agent_runs WHERE id = ?");
    let Some(run) = sqlx::query_as::<_, AgentRun>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(db)
        .await?
    else {
        return Ok(None);
    };
    let rows = sqlx::query("SELECT seq, ts, kind, tool, input, output, text FROM agent_steps WHERE run_id = ? ORDER BY seq")
        .bind(id)
        .fetch_all(db)
        .await?;
    let dec = |s: Option<String>| s.and_then(|s| serde_json::from_str(&s).ok());
    let steps = rows
        .into_iter()
        .map(|r| AgentStep {
            seq: r.get(0),
            ts: r.get(1),
            kind: r.get(2),
            tool: r.get(3),
            input: dec(r.get(4)),
            output: dec(r.get(5)),
            text: r.get(6),
        })
        .collect();
    Ok(Some((run, steps)))
}

/// Model-backed runs since `since`; `chat` selects the interactive budget, otherwise background.
pub async fn runs_since(db: &Db, since: i64, chat: bool) -> Result<u32> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent_runs WHERE started_at >= ? AND model IS NOT NULL AND (kind = 'chat') = ?",
    )
    .bind(since)
    .bind(chat)
    .fetch_one(db)
    .await?;
    Ok(n as u32)
}

// ---------------------------------------------------------------- conversations

pub async fn create_conversation(
    db: &Db,
    id: &str,
    title: &str,
    kind: &str,
    context: Option<&serde_json::Value>,
) -> Result<()> {
    let now = now_ms();
    sqlx::query("INSERT INTO conversations (id, title, kind, context, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(id)
        .bind(title)
        .bind(kind)
        .bind(context.map(|c| c.to_string()))
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn rename_conversation(db: &Db, id: &str, title: &str) -> Result<()> {
    sqlx::query("UPDATE conversations SET title = ? WHERE id = ?")
        .bind(title)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

const CONV_COLS: &str = "c.id, c.title, c.kind, c.context, c.created_at, c.updated_at,
    (SELECT status FROM agent_runs r WHERE r.conversation_id = c.id ORDER BY r.started_at DESC LIMIT 1) AS last_status,
    (SELECT count(*) FROM agent_runs r WHERE r.conversation_id = c.id) AS runs";

/// Newest first; `kind` = "chat" for user conversations, "task" for scheduled ones.
pub async fn list_conversations(
    db: &Db,
    kind: Option<&str>,
    limit: i64,
) -> Result<Vec<Conversation>> {
    let filter = match kind {
        Some("chat") => "WHERE c.kind IN ('chat', 'prompt_gen')",
        Some("task") => "WHERE c.kind NOT IN ('chat', 'prompt_gen')",
        _ => "",
    };
    let sql = format!(
        "SELECT {CONV_COLS} FROM conversations c {filter} ORDER BY c.updated_at DESC LIMIT ?"
    );
    Ok(sqlx::query_as::<_, Conversation>(sqlx::AssertSqlSafe(sql))
        .bind(limit.clamp(1, 500))
        .fetch_all(db)
        .await?)
}

pub async fn get_conversation(db: &Db, id: &str) -> Result<Option<Conversation>> {
    let sql = format!("SELECT {CONV_COLS} FROM conversations c WHERE c.id = ?");
    Ok(sqlx::query_as::<_, Conversation>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(db)
        .await?)
}

/// Runs of a conversation, oldest first, with their steps.
pub async fn conversation_runs(db: &Db, id: &str) -> Result<Vec<(AgentRun, Vec<AgentStep>)>> {
    let sql = format!(
        "SELECT {RUN_COLS} FROM agent_runs WHERE conversation_id = ? ORDER BY started_at, rowid"
    );
    let runs = sqlx::query_as::<_, AgentRun>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_all(db)
        .await?;
    let mut out = Vec::with_capacity(runs.len());
    for r in runs {
        let steps = get_run(db, &r.id)
            .await?
            .map(|(_, s)| s)
            .unwrap_or_default();
        out.push((r, steps));
    }
    Ok(out)
}

/// Deletes a chat conversation with its runs and steps. Scheduled ones are kept (reports link to them).
pub async fn delete_conversation(db: &Db, id: &str) -> Result<bool> {
    let mut tx = db.begin().await?;
    let kind: Option<String> = sqlx::query_scalar("SELECT kind FROM conversations WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    if kind.as_deref() != Some("chat") {
        return Ok(false);
    }
    sqlx::query("DELETE FROM agent_steps WHERE run_id IN (SELECT id FROM agent_runs WHERE conversation_id = ?)")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM agent_runs WHERE conversation_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM conversations WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

// ---------------------------------------------------------------- misc

pub async fn log_notification(
    db: &Db,
    channel: &str,
    event: &str,
    result: &Result<()>,
) -> Result<()> {
    sqlx::query("INSERT INTO notifications (ts, channel, event, ok, error) VALUES (?, ?, ?, ?, ?)")
        .bind(now_ms())
        .bind(channel)
        .bind(event)
        .bind(result.is_ok())
        .bind(result.as_ref().err().map(|e| format!("{e:#}")))
        .execute(db)
        .await?;
    Ok(())
}

pub async fn kv_get(db: &Db, key: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT value FROM kv WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await?)
}

pub async fn kv_set(db: &Db, key: &str, value: &str) -> Result<()> {
    sqlx::query("INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
        .bind(key)
        .bind(value)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(ts: i64, cpu: f64) -> MetricPoint {
        MetricPoint {
            ts,
            cpu_pct: cpu,
            mem_pct: 50.0,
            swap_pct: 0.0,
            disk_pct: 40.0,
            load1: 1.0,
            disk_read_bps: 0.0,
            disk_write_bps: 0.0,
            net_rx_bps: 0.0,
            net_tx_bps: 0.0,
        }
    }

    #[tokio::test]
    async fn metrics_roundtrip_and_rollup() {
        let db = open_memory().await;
        let base = 1_700_000_000_000 / ROLLUP_MS * ROLLUP_MS;
        for i in 0..60 {
            insert_metric(&db, &point(base + i * 10_000, i as f64))
                .await
                .unwrap();
        }
        let (_, pts) = query_metrics(&db, 3_600_000, base + 600_000).await.unwrap();
        assert!(!pts.is_empty());
        rollup_metrics(&db, base, base + 600_000).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM metric_samples WHERE res = 300")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn findings_resolve_and_reopen() {
        let db = open_memory().await;
        let f = NewFinding {
            key: "port:22",
            category: "port",
            severity: "low",
            title: "t",
            detail: "d",
            evidence: "e",
        };
        assert!(upsert_finding(&db, &f).await.unwrap());
        assert!(!upsert_finding(&db, &f).await.unwrap());
        resolve_findings_except(&db, "port", &[]).await.unwrap();
        assert!(list_findings(&db, false).await.unwrap().is_empty());
        assert!(upsert_finding(&db, &f).await.unwrap());
    }
}
