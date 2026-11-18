//! Scheduler: fixed cadences (hourly check, daily report, maintenance) plus state-aware
//! triggers (idle-window audit). Burst-triggered incident analysis lives in `rules`.

use std::time::Duration;

use chrono::{Local, NaiveTime, Timelike};

use crate::config::{parse_hhmm, parse_window};
use crate::model::{ReportKind, now_ms};
use crate::state::Shared;
use crate::store;

pub fn in_window(now: NaiveTime, (start, end): (NaiveTime, NaiveTime)) -> bool {
    if start <= end {
        now >= start && now < end
    } else {
        now >= start || now < end
    }
}

async fn once_per_day(state: &Shared, key: &str) -> bool {
    let today = Local::now().format("%Y-%m-%d").to_string();
    match store::kv_get(&state.db, key).await {
        Ok(Some(d)) if d == today => false,
        Ok(_) => store::kv_set(&state.db, key, &today).await.is_ok(),
        Err(e) => {
            tracing::warn!("scheduler kv: {e:#}");
            false
        }
    }
}

pub fn spawn(state: &Shared) {
    let state = state.clone();
    tokio::spawn(async move {
        let daily_at = parse_hhmm(&state.cfg.schedule.daily_at).expect("validated");
        let idle_window = parse_window(&state.cfg.schedule.idle_window).expect("validated");
        let mut last_hour = Local::now().hour();
        let mut last_rollup = now_ms();
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let now = Local::now();
            let Some(agent) = state.agent().cloned() else {
                continue;
            };

            // 5-minute metric rollups for long-range charts
            if now_ms() - last_rollup >= 300_000 {
                let to = now_ms();
                if let Err(e) = store::rollup_metrics(&state.db, last_rollup - 300_000, to).await {
                    tracing::warn!("metric rollup: {e:#}");
                }
                last_rollup = to;
            }

            // hourly: AI check, warning digest, retention
            if now.hour() != last_hour {
                last_hour = now.hour();
                if state.cfg.schedule.hourly && !state.is_yielding() {
                    agent.trigger_background(ReportKind::Hourly, "schedule:hourly");
                }
                if let Err(e) = state.notifier.warning_digest(&state).await {
                    tracing::warn!("warning digest: {e:#}");
                }
                let s = &state.cfg.storage;
                if let Err(e) =
                    store::apply_retention(&state.db, s.raw_retention_days, s.rollup_retention_days)
                        .await
                {
                    tracing::warn!("retention: {e:#}");
                }
                agent.sandbox().cleanup(Duration::from_secs(3 * 86_400));
            }

            // daily report at the configured local time (or later the same day if missed)
            // wait until some data exists before catching up on a missed daily report
            let warmed_up = now_ms() - state.started_at >= 10 * 60_000;
            if now.time() >= daily_at
                && warmed_up
                && once_per_day(&state, "last_daily_report").await
            {
                agent.trigger_background(ReportKind::Daily, "schedule:daily");
            }

            // quiet window: deep audit once per night when the host is calm for 10 minutes
            let calm = {
                let live = state.read();
                live.cpu_recent.len() >= 60
                    && live
                        .cpu_recent
                        .iter()
                        .rev()
                        .take(60)
                        .all(|c| *c < state.cfg.schedule.idle_cpu_pct)
                    && live.bursts.is_empty()
            };
            let in_idle = in_window(now.time(), idle_window);
            let idle_active = state.read().idle_audit_since.is_some();
            if in_idle
                && calm
                && !state.is_yielding()
                && !idle_active
                && once_per_day(&state, "last_idle_audit").await
            {
                state.write().idle_audit_since = Some(now_ms());
                crate::rules::recompute_mode(&state);
                agent.trigger_background(ReportKind::Audit, "schedule:idle-window");
            } else if idle_active && (!in_idle || !agent.is_running()) {
                // audit mode ends with the window or when the audit run is done
                let started = state.read().idle_audit_since.unwrap_or(0);
                if !in_idle || now_ms() - started > 120_000 {
                    state.write().idle_audit_since = None;
                    crate::rules::recompute_mode(&state);
                }
            }

            crate::tasks::tick(&state).await;
            agent.run_deferred();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_wrap_midnight() {
        let t = |s| NaiveTime::parse_from_str(s, "%H:%M").unwrap();
        assert!(in_window(t("02:00"), (t("01:00"), t("05:00"))));
        assert!(!in_window(t("06:00"), (t("01:00"), t("05:00"))));
        assert!(in_window(t("23:30"), (t("23:00"), t("05:00"))));
        assert!(in_window(t("04:00"), (t("23:00"), t("05:00"))));
        assert!(!in_window(t("12:00"), (t("23:00"), t("05:00"))));
    }
}
