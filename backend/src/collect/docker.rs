//! Docker discovery through read-only API calls only: list, inspect, stats, logs, events.
//! No call in this module can start, stop, restart or modify a container.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use bollard::Docker;
use bollard::query_parameters::{
    EventsOptionsBuilder, ListContainersOptionsBuilder, LogsOptionsBuilder, StatsOptionsBuilder,
};
use futures::StreamExt;

use crate::config::LogKind;
use crate::model::{ContainerInfo, ContainerPoint, Event, now_ms};
use crate::preprocess::Assembler;
use crate::state::Shared;
use crate::{rules, store};

const HISTORY: usize = 60;
const LOOP_WINDOW_MS: i64 = 10 * 60_000;
const LOOP_RESTARTS: i64 = 3;

pub fn connect() -> Result<Docker, bollard::errors::Error> {
    Docker::connect_with_defaults()
}

fn parse_time(s: Option<&str>) -> Option<i64> {
    let s = s?;
    if s.starts_with("0001-") {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.timestamp_millis())
}

#[derive(Default)]
struct Tracker {
    /// container id -> (ts, restart_count) samples
    restarts: HashMap<String, VecDeque<(i64, i64)>>,
    /// container id -> die events
    deaths: HashMap<String, VecDeque<i64>>,
    log_since: HashMap<String, i64>,
    assemblers: HashMap<String, Assembler>,
}

impl Tracker {
    fn restart_loop(&mut self, id: &str, now: i64, count: i64, state: &str) -> bool {
        let q = self.restarts.entry(id.to_string()).or_default();
        q.push_back((now, count));
        while q.front().is_some_and(|(t, _)| now - t > LOOP_WINDOW_MS) {
            q.pop_front();
        }
        let grew = q.front().map(|(_, c)| count - c).unwrap_or(0);
        let deaths = self
            .deaths
            .get(id)
            .map(|d| d.iter().filter(|t| now - **t <= LOOP_WINDOW_MS).count() as i64)
            .unwrap_or(0);
        state == "restarting" || grew >= LOOP_RESTARTS || deaths >= LOOP_RESTARTS
    }
}

pub fn cpu_percent(s: &bollard::models::ContainerStatsResponse) -> f64 {
    let (Some(cpu), Some(pre)) = (s.cpu_stats.as_ref(), s.precpu_stats.as_ref()) else {
        return 0.0;
    };
    let total = cpu
        .cpu_usage
        .as_ref()
        .and_then(|u| u.total_usage)
        .unwrap_or(0) as f64;
    let pre_total = pre
        .cpu_usage
        .as_ref()
        .and_then(|u| u.total_usage)
        .unwrap_or(0) as f64;
    let sys = cpu.system_cpu_usage.unwrap_or(0) as f64;
    let pre_sys = pre.system_cpu_usage.unwrap_or(0) as f64;
    let cpus = cpu.online_cpus.map(f64::from).unwrap_or(1.0).max(1.0);
    let (d_cpu, d_sys) = (total - pre_total, sys - pre_sys);
    if d_cpu > 0.0 && d_sys > 0.0 {
        d_cpu / d_sys * cpus * 100.0
    } else {
        0.0
    }
}

fn mem_used(s: &bollard::models::ContainerStatsResponse) -> (u64, u64) {
    let Some(m) = s.memory_stats.as_ref() else {
        return (0, 0);
    };
    let usage = m.usage.unwrap_or(0);
    // match `docker stats`: subtract page cache
    let cache = m
        .stats
        .as_ref()
        .and_then(|st| {
            st.get("inactive_file")
                .or_else(|| st.get("total_inactive_file"))
                .copied()
        })
        .unwrap_or(0);
    (usage.saturating_sub(cache), m.limit.unwrap_or(0))
}

fn net_totals(s: &bollard::models::ContainerStatsResponse) -> (u64, u64) {
    s.networks
        .as_ref()
        .map(|n| {
            n.values().fold((0, 0), |(r, t), v| {
                (r + v.rx_bytes.unwrap_or(0), t + v.tx_bytes.unwrap_or(0))
            })
        })
        .unwrap_or((0, 0))
}

async fn poll(docker: &Docker, state: &Shared, tracker: &mut Tracker) -> anyhow::Result<()> {
    let list = docker
        .list_containers(Some(
            ListContainersOptionsBuilder::default().all(true).build(),
        ))
        .await?;
    let now = now_ms();
    let mut out = Vec::with_capacity(list.len());
    for c in list {
        let Some(id) = c.id.clone() else { continue };
        let name = c
            .names
            .as_ref()
            .and_then(|n| n.first())
            .map(|n| n.trim_start_matches('/').to_string())
            .unwrap_or_else(|| id[..12.min(id.len())].to_string());
        let inspect = match docker
            .inspect_container(
                &id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
        {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("inspect {name}: {e}");
                continue;
            }
        };
        let st = inspect.state.as_ref();
        let state_str = st
            .and_then(|s| s.status)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".into());
        let running = st.and_then(|s| s.running).unwrap_or(false);
        let restart_count = inspect.restart_count.unwrap_or(0);
        let mut info = ContainerInfo {
            id: id.clone(),
            name: name.clone(),
            image: c.image.clone().unwrap_or_default(),
            state: state_str.clone(),
            status: c.status.clone().unwrap_or_default(),
            // a stopped container keeps its last health status; only running ones count
            health: st
                .filter(|_| running)
                .and_then(|s| s.health.as_ref())
                .and_then(|h| h.status)
                .map(|h| h.to_string())
                .filter(|h| h != "none" && !h.is_empty()),
            restart_count,
            restart_loop: tracker.restart_loop(&id, now, restart_count, &state_str),
            oom_killed: st.and_then(|s| s.oom_killed).unwrap_or(false),
            started_at: parse_time(st.and_then(|s| s.started_at.as_deref())),
            ..Default::default()
        };
        if running {
            let opts = StatsOptionsBuilder::default().stream(false).build();
            if let Some(Ok(stats)) = docker.stats(&id, Some(opts)).next().await {
                info.cpu_pct = cpu_percent(&stats);
                (info.mem_used, info.mem_limit) = mem_used(&stats);
                // docker reports host memory as the limit when none is set; expose that as 0
                if inspect
                    .host_config
                    .as_ref()
                    .and_then(|h| h.memory)
                    .unwrap_or(0)
                    == 0
                {
                    info.mem_limit = 0;
                }
                (info.net_rx, info.net_tx) = net_totals(&stats);
            }
            if state.cfg.docker.follow_logs {
                follow_logs(docker, &id, &name, tracker, state.cfg.docker.max_log_lines).await;
            }
        }
        out.push(info);
    }

    let snapshot = {
        let mut live = state.write();
        for c in &out {
            let h = live.container_history.entry(c.id.clone()).or_default();
            h.push_back(ContainerPoint {
                ts: now,
                cpu_pct: c.cpu_pct,
                mem_used: c.mem_used,
            });
            while h.len() > HISTORY {
                h.pop_front();
            }
        }
        live.container_history
            .retain(|id, _| out.iter().any(|c| &c.id == id));
        live.containers = out.clone();
        out
    };
    tracker
        .restarts
        .retain(|id, _| snapshot.iter().any(|c| &c.id == id));
    state.emit(Event::Containers(snapshot.clone()));
    rules::on_containers(state, &snapshot).await;
    Ok(())
}

async fn follow_logs(
    docker: &Docker,
    id: &str,
    name: &str,
    tracker: &mut Tracker,
    max_lines: usize,
) {
    let now_s = chrono::Utc::now().timestamp();
    let since = *tracker.log_since.entry(id.to_string()).or_insert(now_s);
    if since >= now_s {
        return;
    }
    let opts = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .since(since as i32)
        .until(now_s as i32)
        .tail(&max_lines.to_string())
        .build();
    let source = format!("docker:{name}");
    let pipeline = crate::collect::pipeline();
    pipeline.register(&source, LogKind::Docker, None, Some(name));
    let asm = tracker
        .assemblers
        .entry(id.to_string())
        .or_insert_with(|| Assembler::new(LogKind::Docker));
    let mut stream = docker.logs(id, Some(opts));
    while let Some(item) = stream.next().await {
        let Ok(out) = item else { break };
        let text = String::from_utf8_lossy(&out.into_bytes()).to_string();
        for line in text.lines() {
            if let Some(rec) = asm.push(line) {
                pipeline.ingest(&source, LogKind::Docker, &rec);
            }
        }
    }
    if let Some(rec) = asm.flush() {
        pipeline.ingest(&source, LogKind::Docker, &rec);
    }
    tracker.log_since.insert(id.to_string(), now_s);
}

/// Recent stdout/stderr of one container, redacted. Used by the API and the AI tools.
pub async fn container_logs(
    docker: &Docker,
    id: &str,
    tail: usize,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let opts = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .timestamps(true)
        .tail(&tail.min(2000).to_string())
        .build();
    let mut stream = docker.logs(id, Some(opts));
    let mut lines = Vec::new();
    while let Some(item) = stream.next().await {
        let out = item?;
        let stream_name = match out {
            bollard::container::LogOutput::StdErr { .. } => "stderr",
            _ => "stdout",
        };
        let text = String::from_utf8_lossy(&out.into_bytes()).to_string();
        for line in text.lines() {
            let (ts, rest) = match line.split_once(' ') {
                Some((t, r)) if t.len() > 20 && t.as_bytes()[4] == b'-' => (parse_time(Some(t)), r),
                _ => (None, line),
            };
            lines.push(serde_json::json!({ "ts": ts, "stream": stream_name, "text": crate::preprocess::redact(rest) }));
        }
    }
    Ok(lines)
}

async fn watch_events(
    docker: Docker,
    state: Shared,
    deaths: std::sync::Arc<std::sync::Mutex<HashMap<String, VecDeque<i64>>>>,
) {
    loop {
        let filters: HashMap<&str, Vec<&str>> = HashMap::from([
            ("type", vec!["container"]),
            ("event", vec!["die", "oom", "restart", "health_status"]),
        ]);
        let opts = EventsOptionsBuilder::default().filters(&filters).build();
        let mut stream = docker.events(Some(opts));
        while let Some(ev) = stream.next().await {
            let Ok(ev) = ev else { break };
            let action = ev.action.unwrap_or_default();
            let actor = ev.actor.unwrap_or_default();
            let id = actor.id.unwrap_or_default();
            let attrs = actor.attributes.unwrap_or_default();
            let name = attrs
                .get("name")
                .cloned()
                .unwrap_or_else(|| id.chars().take(12).collect());
            let detail = attrs
                .get("exitCode")
                .map(|c| format!("exit code {c}"))
                .unwrap_or_default();
            let ts = ev.time.map(|t| t * 1000).unwrap_or_else(now_ms);
            if let Err(e) =
                store::insert_container_event(&state.db, ts, &id, &name, &action, &detail).await
            {
                tracing::warn!("storing container event: {e:#}");
            }
            if action == "die" {
                deaths
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .entry(id.clone())
                    .or_default()
                    .push_back(ts);
            }
            rules::on_container_event(&state, &name, &action, &detail).await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub fn spawn(state: &Shared) {
    if !state.cfg.docker.enabled {
        state.set_collector("docker", false, Some("已在配置中关闭".into()));
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        let mut tracker = Tracker::default();
        let deaths = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let mut events_started = false;
        loop {
            match connect() {
                Ok(docker) => {
                    if !events_started {
                        tokio::spawn(watch_events(docker.clone(), state.clone(), deaths.clone()));
                        events_started = true;
                    }
                    {
                        let d = deaths.lock().unwrap_or_else(|e| e.into_inner());
                        tracker.deaths.clone_from(&d);
                    }
                    match poll(&docker, &state, &mut tracker).await {
                        Ok(()) => state.set_collector("docker", true, None),
                        Err(e) => state.set_collector("docker", false, Some(format!("{e}"))),
                    }
                }
                Err(e) => state.set_collector("docker", false, Some(format!("{e}"))),
            }
            let secs =
                state.cfg.collect.container_interval_secs * if state.is_yielding() { 2 } else { 1 };
            tokio::time::sleep(Duration::from_secs(secs)).await;
        }
    });
}
