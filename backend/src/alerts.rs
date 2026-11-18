//! Alert lifecycle: de-duplicated by fingerprint, escalates severity, resolves when the
//! condition clears, and pushes notifications with a per-fingerprint cooldown.

use anyhow::Result;

use crate::config::Severity;
use crate::model::{Alert, AlertCounts, Event, now_ms};
use crate::state::Shared;

pub struct AlertInput<'a> {
    pub severity: Severity,
    pub source: &'a str,
    pub fingerprint: &'a str,
    pub title: &'a str,
    pub summary: &'a str,
    pub suggestion: Option<&'a str>,
}

const COLS: &str = "id, severity, source, title, summary, suggestion, fingerprint, created_at, last_seen, count, status, notified";

pub async fn fetch(db: &crate::store::Db, id: i64) -> Result<Alert> {
    let sql = format!("SELECT {COLS} FROM alerts WHERE id = ?");
    Ok(sqlx::query_as::<_, Alert>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_one(db)
        .await?)
}

/// Raises or refreshes an alert. Returns the stored alert.
pub async fn raise(state: &Shared, a: AlertInput<'_>) -> Result<Alert> {
    let db = &state.db;
    let now = now_ms();
    let existing: Option<(i64, String, Option<i64>)> =
        sqlx::query_as("SELECT id, severity, notified_at FROM alerts WHERE fingerprint = ? AND status = 'open' ORDER BY id DESC LIMIT 1")
            .bind(a.fingerprint)
            .fetch_optional(db)
            .await?;
    let (id, should_notify) = match existing {
        Some((id, sev, notified_at)) => {
            let old = Severity::parse(&sev);
            let new = old.max(a.severity);
            sqlx::query("UPDATE alerts SET severity = ?, last_seen = ?, count = count + 1, summary = ?, suggestion = coalesce(?, suggestion) WHERE id = ?")
                .bind(new.as_str())
                .bind(now)
                .bind(a.summary)
                .bind(a.suggestion)
                .bind(id)
                .execute(db)
                .await?;
            let cooldown = state.cfg.thresholds.alert_cooldown_mins * 60_000;
            let escalated = new > old;
            let cooled = notified_at.is_some_and(|t| now - t >= cooldown);
            (id, escalated || cooled)
        }
        None => {
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO alerts (fingerprint, severity, source, title, summary, suggestion, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            )
            .bind(a.fingerprint)
            .bind(a.severity.as_str())
            .bind(a.source)
            .bind(a.title)
            .bind(a.summary)
            .bind(a.suggestion)
            .bind(now)
            .bind(now)
            .fetch_one(db)
            .await?;
            tracing::info!(
                severity = a.severity.as_str(),
                source = a.source,
                "alert: {}",
                a.title
            );
            (id, true)
        }
    };
    let mut alert = fetch(db, id).await?;
    if should_notify && state.notifier.alert(state, &alert).await {
        sqlx::query("UPDATE alerts SET notified = 1, notified_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(db)
            .await?;
        alert.notified = true;
    }
    state.emit(Event::Alert(alert.clone()));
    Ok(alert)
}

/// Logs and swallows errors: alerting must never take a collector down.
pub async fn raise_logged(state: &Shared, a: AlertInput<'_>) {
    if let Err(e) = raise(state, a).await {
        tracing::warn!("raising alert: {e:#}");
    }
}

pub async fn resolve(state: &Shared, fingerprint: &str) {
    let res: Result<Vec<i64>> = async {
        Ok(sqlx::query_scalar("UPDATE alerts SET status = 'resolved', last_seen = ? WHERE fingerprint = ? AND status = 'open' RETURNING id")
            .bind(now_ms())
            .bind(fingerprint)
            .fetch_all(&state.db)
            .await?)
    }
    .await;
    match res {
        Ok(ids) => {
            for id in ids {
                if let Ok(a) = fetch(&state.db, id).await {
                    state.emit(Event::Alert(a));
                }
            }
        }
        Err(e) => tracing::warn!("resolving alert {fingerprint}: {e:#}"),
    }
}

pub async fn list(db: &crate::store::Db, open_only: bool, limit: i64) -> Result<Vec<Alert>> {
    let sql = format!(
        "SELECT {COLS} FROM alerts WHERE (? = 0 OR status = 'open') ORDER BY last_seen DESC, id DESC LIMIT ?"
    );
    Ok(sqlx::query_as::<_, Alert>(sqlx::AssertSqlSafe(sql))
        .bind(open_only)
        .bind(limit.clamp(1, 1000))
        .fetch_all(db)
        .await?)
}

pub async fn open_counts(db: &crate::store::Db) -> Result<AlertCounts> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT severity, count(*) FROM alerts WHERE status = 'open' GROUP BY severity",
    )
    .fetch_all(db)
    .await?;
    let mut c = AlertCounts::default();
    for (s, n) in rows {
        match s.as_str() {
            "critical" => c.critical = n,
            "warning" => c.warning = n,
            _ => c.info = n,
        }
    }
    Ok(c)
}

/// Open warnings that were never pushed, for the hourly digest (see `mark_notified`).
pub async fn take_unnotified_warnings(db: &crate::store::Db) -> Result<Vec<Alert>> {
    let sql = format!(
        "SELECT {COLS} FROM alerts WHERE status = 'open' AND notified = 0 AND severity = 'warning' ORDER BY created_at"
    );
    let alerts = sqlx::query_as::<_, Alert>(sqlx::AssertSqlSafe(sql))
        .fetch_all(db)
        .await?;
    Ok(alerts)
}

pub async fn mark_notified(db: &crate::store::Db, ids: &[i64]) -> Result<()> {
    let now = now_ms();
    for id in ids {
        sqlx::query("UPDATE alerts SET notified = 1, notified_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(())
}
