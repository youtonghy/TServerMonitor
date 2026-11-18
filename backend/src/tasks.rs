//! User-configurable agent tasks (`scheduled_tasks`), evaluated on the scheduler's 60 s tick.
//!
//! Triggers: fixed interval, daily at a local time, log line/error count since the last run,
//! log burst (called from `rules`), or manual only. Each firing starts a background analysis
//! whose task text comes from the prompt library; the fixed `[schedule]` jobs stay in
//! `schedule.rs` and are listed alongside as read-only.

use anyhow::Result;
use chrono::{DateTime, Local, TimeZone};
use serde::{Deserialize, Serialize};

use crate::agent::TaskSpec;
use crate::model::now_ms;
use crate::settings::{Invalid, TASK_KINDS};
use crate::state::Shared;
use crate::store::Db;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Metric {
    Lines,
    Errors,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Trigger {
    Interval {
        every_mins: u32,
    },
    Daily {
        at: String,
    },
    LogThreshold {
        #[serde(default)]
        source: Option<String>,
        metric: Metric,
        count: i64,
        #[serde(default = "default_min_interval")]
        min_interval_mins: u32,
    },
    Burst,
    Manual,
}

fn default_min_interval() -> u32 {
    30
}

#[derive(Debug, Clone, Serialize)]
pub struct Task {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub builtin: bool,
    pub trigger: Trigger,
    pub prompt_id: String,
    pub route_kind: String,
    pub last_fired_at: Option<i64>,
    pub cursor: Option<i64>,
    pub last_run_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    name: String,
    enabled: bool,
    builtin: bool,
    trigger: String,
    prompt_id: String,
    route_kind: String,
    last_fired_at: Option<i64>,
    cursor: Option<i64>,
    last_run_id: Option<String>,
    created_at: i64,
    updated_at: i64,
}

impl Row {
    fn into_task(self) -> Option<Task> {
        let trigger = match serde_json::from_str(&self.trigger) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("task {}: bad trigger {}: {e}", self.id, self.trigger);
                return None;
            }
        };
        Some(Task {
            id: self.id,
            name: self.name,
            enabled: self.enabled,
            builtin: self.builtin,
            trigger,
            prompt_id: self.prompt_id,
            route_kind: self.route_kind,
            last_fired_at: self.last_fired_at,
            cursor: self.cursor,
            last_run_id: self.last_run_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

const COLS: &str = "id, name, enabled, builtin, trigger, prompt_id, route_kind, last_fired_at, cursor, last_run_id, created_at, updated_at";

pub async fn list(db: &Db) -> Result<Vec<Task>> {
    let sql = format!("SELECT {COLS} FROM scheduled_tasks ORDER BY builtin DESC, created_at");
    Ok(sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql))
        .fetch_all(db)
        .await?
        .into_iter()
        .filter_map(Row::into_task)
        .collect())
}

pub async fn get(db: &Db, id: &str) -> Result<Option<Task>> {
    let sql = format!("SELECT {COLS} FROM scheduled_tasks WHERE id = ?");
    Ok(sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(db)
        .await?
        .and_then(Row::into_task))
}

#[derive(Debug, Deserialize)]
pub struct TaskInput {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub trigger: Option<Trigger>,
    pub prompt_id: Option<String>,
    pub route_kind: Option<String>,
}

fn invalid(msg: impl Into<String>) -> anyhow::Error {
    Invalid(msg.into()).into()
}

fn validate_trigger(t: &Trigger) -> Result<()> {
    match t {
        Trigger::Interval { every_mins } if !(5..=10_080).contains(every_mins) => {
            Err(invalid("间隔需在 5 分钟到 7 天之间"))
        }
        Trigger::Daily { at } => crate::config::parse_hhmm(at)
            .map(|_| ())
            .map_err(|_| invalid("时间格式应为 HH:MM")),
        Trigger::LogThreshold {
            count,
            min_interval_mins,
            source,
            ..
        } => {
            if *count < 1 {
                return Err(invalid("阈值必须大于 0"));
            }
            if *min_interval_mins < 5 {
                return Err(invalid("两次触发的最小间隔不能少于 5 分钟"));
            }
            if source.as_ref().is_some_and(|s| s.len() > 100) {
                return Err(invalid("日志源名称过长"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn validate(db: &Db, name: &str, trigger: &Trigger, prompt: &str, route: &str) -> Result<()> {
    if name.trim().is_empty() || name.chars().count() > 64 {
        return Err(invalid("名称不能为空，且不超过 64 个字符"));
    }
    validate_trigger(trigger)?;
    if crate::agent::library::get(db, prompt).await?.is_none() {
        return Err(invalid("提示词不存在"));
    }
    if !TASK_KINDS.iter().any(|(k, _)| *k == route) {
        return Err(invalid("未知的模型路由类型"));
    }
    Ok(())
}

pub async fn create(db: &Db, inp: TaskInput) -> Result<String> {
    let name = inp.name.unwrap_or_default();
    let trigger = inp.trigger.ok_or_else(|| invalid("缺少触发方式"))?;
    let prompt = inp.prompt_id.unwrap_or_default();
    let route = inp.route_kind.unwrap_or_else(|| "default".into());
    validate(db, &name, &trigger, &prompt, &route).await?;
    let id = format!("t_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let now = now_ms();
    sqlx::query("INSERT INTO scheduled_tasks (id, name, enabled, builtin, trigger, prompt_id, route_kind, cursor, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(name.trim())
        .bind(inp.enabled.unwrap_or(true))
        .bind(serde_json::to_string(&trigger)?)
        .bind(&prompt)
        .bind(&route)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn update(db: &Db, id: &str, inp: TaskInput) -> Result<bool> {
    let Some(cur) = get(db, id).await? else {
        return Ok(false);
    };
    let name = inp.name.unwrap_or(cur.name);
    let trigger_changed = inp.trigger.as_ref().is_some_and(|t| *t != cur.trigger);
    let trigger = inp.trigger.unwrap_or(cur.trigger);
    let prompt = inp.prompt_id.unwrap_or(cur.prompt_id);
    let route = inp.route_kind.unwrap_or(cur.route_kind);
    validate(db, &name, &trigger, &prompt, &route).await?;
    let enabled = inp.enabled.unwrap_or(cur.enabled);
    // re-enabling or retriggering restarts threshold counting from now
    let cursor = if trigger_changed || (enabled && !cur.enabled) {
        Some(now_ms())
    } else {
        cur.cursor
    };
    sqlx::query("UPDATE scheduled_tasks SET name = ?, enabled = ?, trigger = ?, prompt_id = ?, route_kind = ?, cursor = ?, updated_at = ? WHERE id = ?")
        .bind(name.trim())
        .bind(enabled)
        .bind(serde_json::to_string(&trigger)?)
        .bind(&prompt)
        .bind(&route)
        .bind(cursor)
        .bind(now_ms())
        .bind(id)
        .execute(db)
        .await?;
    Ok(true)
}

pub async fn delete(db: &Db, id: &str) -> Result<bool> {
    let Some(t) = get(db, id).await? else {
        return Ok(false);
    };
    if t.builtin {
        return Err(invalid("内置任务不能删除，可以停用"));
    }
    sqlx::query("DELETE FROM scheduled_tasks WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(true)
}

async fn mark_fired(db: &Db, id: &str, at: i64, run_id: Option<&str>) -> Result<()> {
    sqlx::query("UPDATE scheduled_tasks SET last_fired_at = ?, cursor = ?, last_run_id = COALESCE(?, last_run_id) WHERE id = ?")
        .bind(at)
        .bind(at)
        .bind(run_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn log_count_since(
    db: &Db,
    since: i64,
    source: Option<&str>,
    metric: Metric,
) -> Result<i64> {
    let col = match metric {
        Metric::Lines => "lines",
        Metric::Errors => "errors",
    };
    let sql = format!(
        "SELECT COALESCE(SUM({col}), 0) FROM log_rates WHERE minute >= ? AND (? IS NULL OR source = ?)"
    );
    Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(since / 60_000 * 60_000)
        .bind(source)
        .bind(source)
        .fetch_one(db)
        .await?)
}

/// Whether a time-based trigger is due at `now`. Threshold triggers need the log count.
pub fn due(t: &Task, now: DateTime<Local>, log_count: Option<i64>) -> bool {
    let now_ms = now.timestamp_millis();
    let since_last = t.last_fired_at.map(|l| now_ms - l);
    match &t.trigger {
        Trigger::Interval { every_mins } => {
            // the first run waits one full interval after creation
            let base = t.last_fired_at.unwrap_or(t.created_at);
            now_ms - base >= i64::from(*every_mins) * 60_000
        }
        Trigger::Daily { at } => {
            let Ok(at) = crate::config::parse_hhmm(at) else {
                return false;
            };
            let today_at = Local
                .from_local_datetime(&now.date_naive().and_time(at))
                .earliest()
                .map(|d| d.timestamp_millis());
            match today_at {
                // due once the time has passed today and it has not fired since then
                Some(at_ms) => now_ms >= at_ms && t.last_fired_at.is_none_or(|l| l < at_ms),
                None => false,
            }
        }
        Trigger::LogThreshold {
            count,
            min_interval_mins,
            ..
        } => {
            since_last.is_none_or(|d| d >= i64::from(*min_interval_mins) * 60_000)
                && log_count.is_some_and(|n| n >= *count)
        }
        Trigger::Burst | Trigger::Manual => false,
    }
}

fn describe(t: &Trigger) -> String {
    match t {
        Trigger::Interval { every_mins } => format!("每 {every_mins} 分钟"),
        Trigger::Daily { at } => format!("每天 {at}"),
        Trigger::LogThreshold {
            source,
            metric,
            count,
            ..
        } => format!(
            "{}{}达到 {count}",
            source
                .as_deref()
                .map(|s| format!("{s} "))
                .unwrap_or_default(),
            if *metric == Metric::Errors {
                "错误数"
            } else {
                "日志行数"
            }
        ),
        Trigger::Burst => "日志突增".into(),
        Trigger::Manual => "手动".into(),
    }
}

async fn spec(db: &Db, t: &Task) -> Result<Option<TaskSpec>> {
    let Some(prompt) = crate::agent::library::get(db, &t.prompt_id).await? else {
        tracing::warn!("task {}: prompt {} not found", t.id, t.prompt_id);
        return Ok(None);
    };
    Ok(Some(TaskSpec {
        id: t.id.clone(),
        name: t.name.clone(),
        route: t.route_kind.clone(),
        prompt: prompt.body,
    }))
}

/// Starts a task now. Background lane: deferred when busy, so no run id is returned then.
pub async fn fire(state: &Shared, t: &Task, reason: &str) -> Result<Option<String>> {
    let Some(agent) = state.agent().cloned() else {
        return Ok(None);
    };
    let Some(spec) = spec(&state.db, t).await? else {
        return Ok(None);
    };
    let trigger = format!("task:{}:{reason}", t.id);
    let run = agent.trigger_task(spec, &trigger);
    mark_fired(&state.db, &t.id, now_ms(), run.as_deref()).await?;
    tracing::info!("task {} ({}) fired: {reason}", t.id, t.name);
    Ok(run)
}

/// Scheduler tick: fires every enabled task whose trigger is due.
pub async fn tick(state: &Shared) {
    // like the daily report, wait until some data exists after a restart
    if now_ms() - state.started_at < 10 * 60_000 {
        return;
    }
    let list = match list(&state.db).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("loading tasks: {e:#}");
            return;
        }
    };
    let now = Local::now();
    for t in list.into_iter().filter(|t| t.enabled) {
        let count = match &t.trigger {
            Trigger::LogThreshold { source, metric, .. } => {
                let since = t.cursor.or(t.last_fired_at).unwrap_or(t.created_at);
                log_count_since(&state.db, since, source.as_deref(), *metric)
                    .await
                    .ok()
            }
            _ => None,
        };
        if due(&t, now, count) {
            let reason = match count {
                Some(n) => format!("{}（{n}）", describe(&t.trigger)),
                None => describe(&t.trigger),
            };
            if let Err(e) = fire(state, &t, &reason).await {
                tracing::warn!("firing task {}: {e:#}", t.id);
            }
        }
    }
}

/// Called by the burst rule: fires enabled tasks with a burst trigger.
pub async fn on_burst(state: &Shared, sources: &str) {
    let Ok(list) = list(&state.db).await else {
        return;
    };
    for t in list
        .iter()
        .filter(|t| t.enabled && t.trigger == Trigger::Burst)
    {
        if let Err(e) = fire(state, t, &format!("burst:{sources}")).await {
            tracing::warn!("firing task {}: {e:#}", t.id);
        }
    }
}

/// Fixed jobs from `[schedule]`, shown read-only next to the editable tasks.
pub fn system_jobs(state: &Shared) -> serde_json::Value {
    let s = &state.cfg.schedule;
    serde_json::json!([
        { "id": "system:hourly", "name": "小时巡检", "enabled": s.hourly, "trigger": "每小时整点", "prompt_id": "builtin:hourly", "route_kind": "hourly" },
        { "id": "system:daily", "name": "每日运维简报", "enabled": true, "trigger": format!("每天 {}", s.daily_at), "prompt_id": "builtin:daily", "route_kind": "daily" },
        { "id": "system:incident", "name": "异常事件分析", "enabled": true, "trigger": format!("日志错误突增（基线 {} 倍且每分钟 ≥ {}）", s.burst_factor, s.burst_min_errors_per_min), "prompt_id": "builtin:incident", "route_kind": "incident" },
        { "id": "system:audit", "name": "深度审计", "enabled": true, "trigger": format!("空闲窗口 {}（CPU < {}%）", s.idle_window, s.idle_cpu_pct), "prompt_id": "builtin:audit", "route_kind": "audit" },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(trigger: Trigger, created: i64, last: Option<i64>) -> Task {
        Task {
            id: "t".into(),
            name: "t".into(),
            enabled: true,
            builtin: false,
            trigger,
            prompt_id: "builtin:log_scan".into(),
            route_kind: "log_scan".into(),
            last_fired_at: last,
            cursor: None,
            last_run_id: None,
            created_at: created,
            updated_at: created,
        }
    }

    fn at(h: u32, m: u32) -> DateTime<Local> {
        Local
            .with_ymd_and_hms(2026, 11, 18, h, m, 0)
            .earliest()
            .unwrap()
    }

    #[test]
    fn interval_waits_one_period() {
        let created = at(10, 0).timestamp_millis();
        let t = task(Trigger::Interval { every_mins: 60 }, created, None);
        assert!(!due(&t, at(10, 30), None));
        assert!(due(&t, at(11, 0), None));
        let t = task(
            Trigger::Interval { every_mins: 60 },
            created,
            Some(at(11, 0).timestamp_millis()),
        );
        assert!(!due(&t, at(11, 59), None));
    }

    #[test]
    fn daily_fires_once_after_time() {
        let created = at(1, 0).timestamp_millis();
        let t = task(Trigger::Daily { at: "03:30".into() }, created, None);
        assert!(!due(&t, at(3, 0), None));
        assert!(due(&t, at(3, 31), None));
        // catch-up later the same day
        assert!(due(&t, at(9, 0), None));
        let fired = task(
            Trigger::Daily { at: "03:30".into() },
            created,
            Some(at(3, 31).timestamp_millis()),
        );
        assert!(!due(&fired, at(9, 0), None));
    }

    #[test]
    fn threshold_needs_count_and_spacing() {
        let trig = Trigger::LogThreshold {
            source: None,
            metric: Metric::Errors,
            count: 100,
            min_interval_mins: 30,
        };
        let t = task(trig.clone(), 0, None);
        assert!(!due(&t, at(10, 0), Some(99)));
        assert!(due(&t, at(10, 0), Some(100)));
        let recent = task(trig, 0, Some(at(9, 50).timestamp_millis()));
        assert!(!due(&recent, at(10, 0), Some(500)));
    }

    #[tokio::test]
    async fn seeded_tasks_and_crud() {
        let db = crate::store::open_memory().await;
        let all = list(&db).await.unwrap();
        assert!(
            all.iter()
                .any(|t| t.id == "t_security_check" && t.enabled && t.builtin)
        );
        assert!(delete(&db, "t_security_check").await.is_err());
        let bad = create(
            &db,
            TaskInput {
                name: Some("x".into()),
                enabled: None,
                trigger: Some(Trigger::Interval { every_mins: 1 }),
                prompt_id: Some("builtin:log_scan".into()),
                route_kind: None,
            },
        )
        .await;
        assert!(bad.is_err());
        let id = create(
            &db,
            TaskInput {
                name: Some("错误阈值".into()),
                enabled: None,
                trigger: Some(Trigger::LogThreshold {
                    source: Some("nginx".into()),
                    metric: Metric::Errors,
                    count: 50,
                    min_interval_mins: 30,
                }),
                prompt_id: Some("builtin:log_scan".into()),
                route_kind: Some("log_scan".into()),
            },
        )
        .await
        .unwrap();
        crate::store::add_log_rates(
            &db,
            &[
                crate::store::RateRow {
                    minute: now_ms(),
                    source: "nginx",
                    lines: 300,
                    errors: 60,
                    date: "2026-11-18".into(),
                },
                crate::store::RateRow {
                    minute: now_ms(),
                    source: "php",
                    lines: 10,
                    errors: 10,
                    date: "2026-11-18".into(),
                },
            ],
        )
        .await
        .unwrap();
        let t = get(&db, &id).await.unwrap().unwrap();
        let n = log_count_since(
            &db,
            t.cursor.unwrap() - 60_000,
            Some("nginx"),
            Metric::Errors,
        )
        .await
        .unwrap();
        assert_eq!(n, 60);
        assert!(delete(&db, &id).await.unwrap());
    }
}
