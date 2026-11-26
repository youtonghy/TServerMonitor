//! Rule engine: thresholds, burst detection, mode switching, rule-based health score and
//! the rule-based diagnosis used when the AI is unavailable.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use crate::alerts::{self, AlertInput};
use crate::collect::logs::BurstCheck;
use crate::collect::security::Check;
use crate::config::Severity;
use crate::model::{
    AlertSeverity, Anomaly, Confidence, ContainerInfo, DbStatus, Diagnosis, Event, Finding,
    FindingSeverity, HealthDimensions, HostMetrics, Mode, ModeState, Priority, RecCategory,
    Recommendation, ReportKind, RootCause, SecurityRisk, now_ms, pct,
};
use crate::state::{Live, Shared};

#[derive(Default)]
struct RuleState {
    /// condition key -> consecutive samples over threshold (positive) or under (negative)
    streaks: HashMap<String, i32>,
    yield_streak: i32,
    calm_streak: i32,
    /// source -> last time a burst was seen (ms)
    burst_seen: HashMap<String, i64>,
    last_incident: i64,
    /// access alert fingerprint -> last time its condition held (ms)
    access_seen: HashMap<String, i64>,
}

static RS: LazyLock<Mutex<RuleState>> = LazyLock::new(|| Mutex::new(RuleState::default()));

fn rs() -> std::sync::MutexGuard<'static, RuleState> {
    RS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Updates a streak and returns its new length (positive when over).
fn streak(key: &str, over: bool) -> i32 {
    let mut s = rs();
    let v = s.streaks.entry(key.to_string()).or_insert(0);
    *v = match (over, *v > 0) {
        (true, true) => *v + 1,
        (true, false) => 1,
        (false, false) => *v - 1,
        (false, true) => -1,
    };
    *v
}

struct Threshold<'a> {
    key: String,
    value: f64,
    warn: f64,
    crit: Option<f64>,
    title: &'a str,
    unit: &'a str,
    suggestion: &'a str,
}

async fn check_threshold(state: &Shared, t: Threshold<'_>) {
    let n = state.cfg.thresholds.sustain_samples as i32;
    let s = streak(&t.key, t.value >= t.warn);
    if s >= n {
        let crit = t.crit.is_some_and(|c| t.value >= c);
        let severity = if crit {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let summary = format!(
            "{} 当前 {:.1}{}（阈值 {:.0}{}），已持续 {} 个采样周期。",
            t.title, t.value, t.unit, t.warn, t.unit, s
        );
        alerts::raise_logged(
            state,
            AlertInput {
                severity,
                source: "host",
                fingerprint: &t.key,
                title: t.title,
                summary: &summary,
                suggestion: Some(t.suggestion),
            },
        )
        .await;
    } else if s == -n {
        alerts::resolve(state, &t.key).await;
    }
}

pub async fn on_host_sample(state: &Shared, m: &HostMetrics) {
    let th = &state.cfg.thresholds;
    check_threshold(
        state,
        Threshold {
            key: "host:cpu".into(),
            value: m.cpu_pct,
            warn: th.cpu_warn,
            crit: Some(th.cpu_crit),
            title: "CPU 使用率过高",
            unit: "%",
            suggestion: "查看总览页 CPU 曲线与容器页资源排行，定位高占用进程；必要时检查慢请求与死循环。",
        },
    )
    .await;
    check_threshold(
        state,
        Threshold {
            key: "host:mem".into(),
            value: m.mem_pct(),
            warn: th.mem_warn,
            crit: Some(th.mem_crit),
            title: "内存使用率过高",
            unit: "%",
            suggestion: "检查 PHP-FPM 进程数（pm.max_children）、Node 进程堆大小与数据库缓冲区配置，防止触发 OOM。",
        },
    )
    .await;
    if m.swap_total > 0 {
        check_threshold(
            state,
            Threshold {
                key: "host:swap".into(),
                value: m.swap_pct(),
                warn: th.swap_warn,
                crit: None,
                title: "Swap 使用率过高",
                unit: "%",
                suggestion: "Swap 占用过高会显著拖慢服务，建议排查内存占用或扩容内存。",
            },
        )
        .await;
    }
    for d in &m.disks {
        check_threshold(
            state,
            Threshold {
                key: format!("host:disk:{}", d.mount),
                value: pct(d.used, d.total),
                warn: th.disk_warn,
                crit: Some(th.disk_crit),
                title: "磁盘空间不足",
                unit: "%",
                suggestion: "清理旧日志（检查 logrotate 配置）、Docker 镜像与构建缓存（docker system df），或扩容磁盘。",
            },
        )
        .await;
    }

    // business first: detect a busy host and postpone deep work
    let sc = &state.cfg.schedule;
    let busy =
        m.cpu_pct >= sc.yield_cpu_pct || m.load1 / m.cpu_cores as f64 >= sc.yield_load_per_core;
    let changed = {
        let mut r = rs();
        if busy {
            r.yield_streak += 1;
            r.calm_streak = 0;
        } else {
            r.calm_streak += 1;
            r.yield_streak = 0;
        }
        let (ys, cs) = (r.yield_streak, r.calm_streak);
        drop(r);
        let mut live = state.write();
        if ys >= 3 && live.yield_reason.is_none() {
            live.yield_reason = Some(format!(
                "主机繁忙（CPU {:.0}%，负载 {:.2}），暂停深度分析并降低采样频率",
                m.cpu_pct, m.load1
            ));
            true
        } else if cs >= 6 && live.yield_reason.is_some() {
            live.yield_reason = None;
            true
        } else {
            false
        }
    };
    if changed {
        recompute_mode(state);
    }
}

pub async fn on_log_checks(state: &Shared, checks: &[BurstCheck]) {
    let sc = &state.cfg.schedule;
    let now = now_ms();
    let mut started = Vec::new();
    for c in checks {
        let err_threshold = (sc.burst_factor * c.baseline_errors).max(sc.burst_min_errors_per_min);
        let line_threshold = (sc.burst_factor * c.baseline_lines).max(600.0);
        let err_burst = c.errors_this_min >= err_threshold;
        let line_burst = c.baseline_lines > 0.0 && c.lines_this_min >= line_threshold;
        let fp = format!("log-burst:{}", c.source);
        if err_burst || line_burst {
            rs().burst_seen.insert(c.source.clone(), now);
            let is_new = {
                let mut live = state.write();
                let new = !live.bursts.contains_key(&c.source);
                live.bursts.entry(c.source.clone()).or_insert(now);
                new
            };
            let (title, summary) = if err_burst {
                (
                    format!("{} 错误日志激增", c.source),
                    format!(
                        "本分钟已出现 {:.0} 条错误（基线约 {:.1} 条/分钟，阈值 {:.0}）。已切换到深度日志分析模式。",
                        c.errors_this_min, c.baseline_errors, err_threshold
                    ),
                )
            } else {
                (
                    format!("{} 日志量激增", c.source),
                    format!(
                        "本分钟已写入 {:.0} 行日志（基线约 {:.0} 行/分钟）。",
                        c.lines_this_min, c.baseline_lines
                    ),
                )
            };
            let severity = if err_burst && c.errors_this_min >= err_threshold * 5.0 {
                Severity::Critical
            } else {
                Severity::Warning
            };
            alerts::raise_logged(
                state,
                AlertInput {
                    severity,
                    source: &c.source,
                    fingerprint: &fp,
                    title: &title,
                    summary: &summary,
                    suggestion: Some(
                        "打开日志页查看该来源的错误聚类；AI 将自动对本次突增做根因分析。",
                    ),
                },
            )
            .await;
            if is_new {
                started.push(c.source.clone());
            }
        }
    }
    // a burst ends after 10 quiet minutes
    let ended: Vec<String> = {
        let seen = rs().burst_seen.clone();
        let mut live = state.write();
        let ended: Vec<String> = live
            .bursts
            .keys()
            .filter(|s| seen.get(*s).is_none_or(|t| now - t > 10 * 60_000))
            .cloned()
            .collect();
        for s in &ended {
            live.bursts.remove(s);
        }
        ended
    };
    for s in &ended {
        alerts::resolve(state, &format!("log-burst:{s}")).await;
    }
    if !started.is_empty() || !ended.is_empty() {
        recompute_mode(state);
    }
    if !started.is_empty() {
        let cooldown = sc.burst_cooldown_mins * 60_000;
        let fire = {
            let mut r = rs();
            if now - r.last_incident >= cooldown {
                r.last_incident = now;
                true
            } else {
                false
            }
        };
        if fire && let Some(agent) = state.agent() {
            agent.trigger_background(
                ReportKind::Incident,
                &format!("burst:{}", started.join(",")),
            );
        }
        if fire {
            crate::tasks::on_burst(state, &started.join(",")).await;
        }
    }
}

/// An access-log condition that should be alerting.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessCond {
    pub fingerprint: String,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    pub suggestion: &'static str,
}

/// Evaluates the last-5-minutes access statistics (client addresses unmasked).
pub fn access_conditions(
    s: &crate::collect::access::AccessStats,
    t: &crate::config::Thresholds,
) -> Vec<AccessCond> {
    let mut out = Vec::new();
    let mins = s.window_mins.max(1) as u64;
    if s.requests >= t.access_min_requests && s.error_rate_5xx >= t.access_5xx_warn {
        let crit = s.error_rate_5xx >= t.access_5xx_crit;
        let worst = s
            .top_paths
            .iter()
            .filter(|p| p.s5xx > 0)
            .max_by_key(|p| p.s5xx)
            .map(|p| format!("；最多的是 {}（{} 次）", p.path, p.s5xx))
            .unwrap_or_default();
        out.push(AccessCond {
            fingerprint: "access:5xx".into(),
            severity: if crit { Severity::Critical } else { Severity::Warning },
            title: format!("网站 5xx 比例 {:.1}%", s.error_rate_5xx * 100.0),
            summary: format!(
                "最近 {} 分钟 {} 个请求中有 {} 个 5xx{worst}。",
                s.window_mins, s.requests, s.status[3]
            ),
            suggestion: "查看 nginx 错误日志与上游服务状态（容器、PHP-FPM、Node 进程），确认是否刚发布或上游超时。",
        });
    }
    for ip in &s.top_ips {
        if ip.ip == "(other)" {
            continue;
        }
        if ip.requests / mins >= t.access_flood_per_min {
            out.push(AccessCond {
                fingerprint: format!("access:flood:{}", ip.ip),
                severity: Severity::Warning,
                title: format!("{} 请求量异常", ip.ip),
                summary: format!(
                    "最近 {} 分钟该地址发起 {} 个请求（约 {} 次/分钟，阈值 {}）。",
                    s.window_mins,
                    ip.requests,
                    ip.requests / mins,
                    t.access_flood_per_min
                ),
                suggestion: "确认是否为正常爬虫或内部服务；恶意流量可在防火墙页按来源地址添加拒绝规则，或在 nginx 中配置 limit_req。",
            });
        }
    }
    for ip in &s.suspicious {
        if ip.scan >= t.access_scan_hits {
            out.push(AccessCond {
                fingerprint: format!("access:scan:{}", ip.ip),
                severity: Severity::Warning,
                title: format!("{} 正在扫描敏感路径", ip.ip),
                summary: format!(
                    "最近 {} 分钟该地址访问了 {} 次典型扫描路径（如 /.env、/wp-login.php），共 {} 个请求、{} 个 4xx。",
                    s.window_mins, ip.scan, ip.requests, ip.s4xx
                ),
                suggestion: "确认没有敏感文件可被访问；可在防火墙页对该地址添加拒绝规则。",
            });
        }
    }
    out
}

/// Raises / refreshes access alerts and resolves those quiet for 5 minutes.
pub async fn on_access(state: &Shared, stats: &crate::collect::access::AccessStats) {
    let now = now_ms();
    let conds = access_conditions(stats, &state.cfg.thresholds);
    for c in &conds {
        rs().access_seen.insert(c.fingerprint.clone(), now);
        alerts::raise_logged(
            state,
            AlertInput {
                severity: c.severity,
                source: "access",
                fingerprint: &c.fingerprint,
                title: &c.title,
                summary: &c.summary,
                suggestion: Some(c.suggestion),
            },
        )
        .await;
    }
    let quiet: Vec<String> = {
        let mut r = rs();
        let q: Vec<String> = r
            .access_seen
            .iter()
            .filter(|(_, t)| now - **t > 5 * 60_000)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &q {
            r.access_seen.remove(k);
        }
        q
    };
    for fp in quiet {
        alerts::resolve(state, &fp).await;
    }
}

pub async fn on_containers(state: &Shared, list: &[ContainerInfo]) {
    for c in list {
        let fp = format!("container-loop:{}", c.name);
        if c.restart_loop {
            let summary = format!(
                "容器 {} 处于重启循环（状态 {}，累计重启 {} 次）。",
                c.name, c.state, c.restart_count
            );
            alerts::raise_logged(
                state,
                AlertInput {
                    severity: Severity::Critical,
                    source: "docker",
                    fingerprint: &fp,
                    title: &format!("容器 {} 反复重启", c.name),
                    summary: &summary,
                    suggestion: Some(
                        "查看容器页中该容器的最近日志，检查启动命令、依赖服务与健康检查配置。",
                    ),
                },
            )
            .await;
        } else {
            alerts::resolve(state, &fp).await;
        }
        let fp = format!("container-oom:{}", c.name);
        if c.oom_killed {
            alerts::raise_logged(
                state,
                AlertInput {
                    severity: Severity::Critical,
                    source: "docker",
                    fingerprint: &fp,
                    title: &format!("容器 {} 发生内存溢出（OOM）", c.name),
                    summary: &format!("容器 {} 上次退出因内存超限被内核终止。", c.name),
                    suggestion: Some("提高容器内存限额或排查内存泄漏（对比容器页的内存曲线）。"),
                },
            )
            .await;
        } else {
            alerts::resolve(state, &fp).await;
        }
        let fp = format!("container-unhealthy:{}", c.name);
        if c.health.as_deref() == Some("unhealthy") {
            alerts::raise_logged(
                state,
                AlertInput {
                    severity: Severity::Warning,
                    source: "docker",
                    fingerprint: &fp,
                    title: &format!("容器 {} 健康检查失败", c.name),
                    summary: &format!("容器 {} 的健康检查状态为 unhealthy。", c.name),
                    suggestion: None,
                },
            )
            .await;
        } else {
            alerts::resolve(state, &fp).await;
        }
        let fp = format!("container-mem:{}", c.name);
        let usage = pct(c.mem_used, c.mem_limit);
        if c.mem_limit > 0 && usage >= 90.0 {
            alerts::raise_logged(
                state,
                AlertInput {
                    severity: Severity::Warning,
                    source: "docker",
                    fingerprint: &fp,
                    title: &format!("容器 {} 内存接近限额", c.name),
                    summary: &format!("容器 {} 内存使用已达限额的 {usage:.0}%。", c.name),
                    suggestion: Some("继续增长将触发 OOM，建议提高限额或排查内存泄漏。"),
                },
            )
            .await;
        } else if usage < 85.0 {
            alerts::resolve(state, &fp).await;
        }
    }
}

pub async fn on_container_event(state: &Shared, name: &str, action: &str, detail: &str) {
    if action == "oom" {
        alerts::raise_logged(
            state,
            AlertInput {
                severity: Severity::Critical,
                source: "docker",
                fingerprint: &format!("container-oom:{name}"),
                title: &format!("容器 {name} 发生内存溢出（OOM）"),
                summary: &format!("Docker 报告容器 {name} 触发 OOM。{detail}"),
                suggestion: Some("提高容器内存限额或排查内存泄漏。"),
            },
        )
        .await;
    }
}

pub async fn on_new_finding(state: &Shared, c: &Check) {
    let severity = match c.severity {
        "critical" => Severity::Critical,
        "high" => Severity::Warning,
        _ => return,
    };
    alerts::raise_logged(
        state,
        AlertInput {
            severity,
            source: "security",
            fingerprint: &format!("finding:{}", c.key),
            title: &c.title,
            summary: &c.detail,
            suggestion: None,
        },
    )
    .await;
}

pub async fn on_db_status(state: &Shared, s: &DbStatus) {
    let fp = format!("db-down:{}", s.name);
    if s.ok {
        alerts::resolve(state, &fp).await;
    } else {
        alerts::raise_logged(
            state,
            AlertInput {
                severity: Severity::Warning,
                source: "database",
                fingerprint: &fp,
                title: &format!("数据库 {} 指标采集失败", s.name),
                summary: s.error.as_deref().unwrap_or("未知错误"),
                suggestion: Some("确认数据库是否存活，以及只读监控账号与 DSN 是否正确。"),
            },
        )
        .await;
    }
    let fp = format!("db-conn:{}", s.name);
    match s.metrics.get("connection_usage_pct") {
        Some(u) if *u >= 80.0 => {
            alerts::raise_logged(
                state,
                AlertInput {
                    severity: if *u >= 95.0 {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    },
                    source: "database",
                    fingerprint: &fp,
                    title: &format!("数据库 {} 连接数接近上限", s.name),
                    summary: &format!("连接使用率 {u:.0}%。"),
                    suggestion: Some("检查应用连接池大小与连接泄漏，或调高 max_connections。"),
                },
            )
            .await;
        }
        _ => alerts::resolve(state, &fp).await,
    }
}

/// Mode priority: yield > high_log > idle_audit > normal.
pub fn recompute_mode(state: &Shared) {
    let ev = {
        let mut live = state.write();
        let (mode, reason) = if let Some(r) = &live.yield_reason {
            (Mode::Yield, r.clone())
        } else if !live.bursts.is_empty() {
            (
                Mode::HighLog,
                format!(
                    "检测到日志突增：{}",
                    live.bursts.keys().cloned().collect::<Vec<_>>().join("、")
                ),
            )
        } else if live.idle_audit_since.is_some() {
            (
                Mode::IdleAudit,
                "业务空闲窗口，执行历史回溯与深度审计".to_string(),
            )
        } else {
            (Mode::Normal, "常规调度".to_string())
        };
        if live
            .mode
            .as_ref()
            .is_some_and(|m| m.mode == mode && m.reason == reason)
        {
            return;
        }
        let since = live
            .mode
            .as_ref()
            .filter(|m| m.mode == mode)
            .map(|m| m.since)
            .unwrap_or_else(now_ms);
        let ms = ModeState {
            mode,
            reason,
            since,
        };
        live.mode = Some(ms.clone());
        ms
    };
    tracing::info!("mode -> {:?}: {}", ev.mode, ev.reason);
    state.emit(Event::Mode(ev));
}

// ---------------------------------------------------------------- health score

fn finding_weight(sev: &str) -> f64 {
    match sev {
        "critical" => 40.0,
        "high" => 20.0,
        "medium" => 8.0,
        "low" => 3.0,
        _ => 0.0,
    }
}

pub fn dimensions(live: &Live, findings: &[Finding]) -> HealthDimensions {
    let ramp =
        |v: f64, from: f64, to: f64| 100.0 - ((v - from) / (to - from) * 100.0).clamp(0.0, 100.0);
    let (cpu, memory, disk) = match &live.host {
        Some(h) => {
            let recent: Vec<f64> = live.cpu_recent.iter().rev().take(30).copied().collect();
            let avg = if recent.is_empty() {
                h.cpu_pct
            } else {
                recent.iter().sum::<f64>() / recent.len() as f64
            };
            let mem = ramp(h.mem_pct(), 70.0, 100.0) - (h.swap_pct() / 2.0).min(20.0);
            (ramp(avg, 60.0, 100.0), mem, ramp(h.disk_pct(), 70.0, 100.0))
        }
        None => (100.0, 100.0, 100.0),
    };
    let err_rate: f64 = live.log_sources.values().map(|s| s.errors_per_min).sum();
    let logs = 100.0 - (err_rate * 1.5).min(50.0) - 30.0 * live.bursts.len() as f64;
    let security = 100.0
        - findings
            .iter()
            .filter(|f| !f.resolved)
            .map(|f| finding_weight(&f.severity))
            .sum::<f64>();
    let containers = 100.0
        - live
            .containers
            .iter()
            .map(|c| {
                30.0 * f64::from(u8::from(c.restart_loop))
                    + 25.0 * f64::from(u8::from(c.oom_killed))
                    + 10.0 * f64::from(u8::from(c.health.as_deref() == Some("unhealthy")))
            })
            .sum::<f64>();
    let database = 100.0
        - live
            .dbs
            .iter()
            .map(|d| {
                if !d.ok {
                    50.0
                } else {
                    (d.metrics
                        .get("connection_usage_pct")
                        .copied()
                        .unwrap_or(0.0)
                        - 70.0)
                        .max(0.0)
                        * 1.5
                }
            })
            .sum::<f64>();
    HealthDimensions {
        cpu,
        memory,
        disk,
        logs,
        security,
        containers,
        database,
    }
    .clamp()
}

pub fn overall(d: &HealthDimensions) -> f64 {
    let weighted = d.cpu * 0.15
        + d.memory * 0.15
        + d.disk * 0.15
        + d.logs * 0.15
        + d.security * 0.15
        + d.containers * 0.15
        + d.database * 0.10;
    let worst = [
        d.cpu,
        d.memory,
        d.disk,
        d.logs,
        d.security,
        d.containers,
        d.database,
    ]
    .into_iter()
    .fold(100.0, f64::min);
    // one failing dimension must visibly drag the score down
    weighted.min(worst + 35.0).round()
}

// ---------------------------------------------------------------- rule-based diagnosis

fn fsev(s: &str) -> FindingSeverity {
    match s {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        _ => FindingSeverity::Info,
    }
}

/// Deterministic diagnosis used when no model is available or a model run failed.
pub async fn fallback_diagnosis(state: &Shared, kind: ReportKind) -> anyhow::Result<Diagnosis> {
    let findings = crate::store::list_findings(&state.db, false).await?;
    let open = alerts::list(&state.db, true, 50).await?;
    let since = now_ms()
        - if kind == ReportKind::Daily {
            24 * 3_600_000
        } else {
            3_600_000
        };
    let top_errors = crate::store::query_clusters(
        &state.db,
        &crate::store::ClusterQuery {
            level: Some("error"),
            since: Some(since),
            limit: 5,
            order_by_count: true,
            ..Default::default()
        },
    )
    .await?;
    let slow = crate::store::query_clusters(
        &state.db,
        &crate::store::ClusterQuery {
            level: Some("slow"),
            since: Some(since),
            limit: 3,
            order_by_count: true,
            ..Default::default()
        },
    )
    .await?;

    let live = state.read();
    let dims = dimensions(&live, &findings);
    let score = overall(&dims);
    let mut root_causes = Vec::new();
    let mut recs = Vec::new();
    let mut anomalies = Vec::new();

    for (source, since) in &live.bursts {
        root_causes.push(RootCause {
            title: format!("{source} 日志突增"),
            evidence: format!(
                "自 {} 起错误/日志速率超过基线 {} 倍",
                fmt_time(*since),
                state.cfg.schedule.burst_factor
            ),
            confidence: Confidence::Medium,
        });
    }
    for c in top_errors.iter().take(3) {
        root_causes.push(RootCause {
            title: format!("高频错误：{}", truncate(&c.template, 80)),
            evidence: format!(
                "来源 {}，时间窗内累计 {} 次，最近一次 {}",
                c.source,
                c.count,
                fmt_time(c.last_seen)
            ),
            confidence: Confidence::Low,
        });
        recs.push(Recommendation {
            title: format!("修复 {} 中的高频错误", c.source),
            category: RecCategory::Code,
            priority: if c.count > 100 {
                Priority::High
            } else {
                Priority::Medium
            },
            detail: format!(
                "错误模板：{}\n示例：{}",
                c.template,
                truncate(&c.sample, 300)
            ),
            expected_impact: "减少错误日志噪音与用户可见故障".into(),
        });
    }
    for c in &slow {
        recs.push(Recommendation {
            title: format!("优化慢执行：{}", truncate(&c.template, 60)),
            category: if c.source.contains("mysql") || c.template.to_uppercase().contains("SELECT")
            {
                RecCategory::Database
            } else {
                RecCategory::Code
            },
            priority: Priority::Medium,
            detail: format!(
                "来源 {} 累计 {} 次慢记录。建议检查索引、N+1 查询或外部调用超时。",
                c.source, c.count
            ),
            expected_impact: "降低接口延迟".into(),
        });
    }
    if let Some(h) = &live.host {
        if h.swap_total > 0 && h.swap_pct() > 30.0 {
            recs.push(Recommendation {
                title: "降低 Swap 使用".into(),
                category: RecCategory::Config,
                priority: Priority::Medium,
                detail: format!(
                    "Swap 已用 {:.0}%。考虑调低 vm.swappiness、减少 PHP-FPM 子进程数或扩容内存。",
                    h.swap_pct()
                ),
                expected_impact: "减少因换页导致的延迟抖动".into(),
            });
        }
        if h.disk_pct() > 80.0 {
            recs.push(Recommendation {
                title: "释放磁盘空间".into(),
                category: RecCategory::Infra,
                priority: if h.disk_pct() > 90.0 {
                    Priority::High
                } else {
                    Priority::Medium
                },
                detail: "检查 logrotate 配置、清理 Docker 无用镜像与构建缓存，或扩容磁盘。".into(),
                expected_impact: "避免磁盘写满导致服务中断".into(),
            });
        }
    }
    for c in live
        .containers
        .iter()
        .filter(|c| c.restart_loop || c.oom_killed)
    {
        recs.push(Recommendation {
            title: format!("处理容器 {} 的异常重启", c.name),
            category: RecCategory::Infra,
            priority: Priority::High,
            detail: format!(
                "状态 {}，重启 {} 次，OOM={}。检查启动日志与资源限额。",
                c.state, c.restart_count, c.oom_killed
            ),
            expected_impact: "恢复服务稳定性".into(),
        });
    }
    drop(live);

    let security_risks: Vec<SecurityRisk> = findings
        .iter()
        .filter(|f| matches!(f.severity.as_str(), "critical" | "high" | "medium"))
        .take(10)
        .map(|f| SecurityRisk {
            title: f.title.clone(),
            severity: fsev(&f.severity),
            detail: f.evidence.clone(),
            recommendation: f.detail.clone(),
        })
        .collect();
    for r in security_risks
        .iter()
        .filter(|r| r.severity >= FindingSeverity::High)
        .take(3)
    {
        recs.push(Recommendation {
            title: format!("处理安全隐患：{}", r.title),
            category: RecCategory::Security,
            priority: Priority::High,
            detail: r.recommendation.clone(),
            expected_impact: "缩小攻击面".into(),
        });
    }
    for a in open.iter().take(8) {
        anomalies.push(Anomaly {
            title: a.title.clone(),
            detail: a.summary.clone(),
            severity: match a.severity.as_str() {
                "critical" => AlertSeverity::Critical,
                "warning" => AlertSeverity::Warning,
                _ => AlertSeverity::Info,
            },
        });
    }

    let status = match score as i64 {
        85.. => "整体运行平稳",
        65..=84 => "存在需要关注的问题",
        _ => "存在明显风险，需要尽快处理",
    };
    let summary = format!(
        "{status}（规则评分 {score:.0}）。当前未启用 AI 分析或 AI 分析失败，本报告由内置规则生成：{} 条未处理告警，{} 项安全发现，{} 类高频错误。",
        open.len(),
        findings.len(),
        top_errors.len()
    );
    Ok(Diagnosis {
        health_score: score,
        summary,
        dimensions: dims,
        root_causes,
        security_risks,
        recommendations: recs,
        anomalies,
    }
    .normalized())
}

pub fn fmt_time(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_alert_conditions() {
        let a = crate::collect::access::Access::default();
        let t = 1_700_000_000_000;
        for i in 0..200 {
            let status = if i % 4 == 0 { 502 } else { 200 };
            a.record(
                &format!(
                    r#"10.0.0.{} - - [x] "GET /api HTTP/1.1" {status} 1"#,
                    i % 50
                ),
                t,
            );
        }
        for _ in 0..25 {
            a.record(r#"192.0.2.66 - - [x] "GET /.env HTTP/1.1" 404 0"#, t);
        }
        let th = crate::config::Thresholds::default();
        let c = access_conditions(&a.stats(5, t, 50, false), &th);
        let fps: Vec<&str> = c.iter().map(|c| c.fingerprint.as_str()).collect();
        assert!(fps.contains(&"access:5xx"), "{fps:?}");
        assert!(fps.contains(&"access:scan:192.0.2.66"), "{fps:?}");
        assert_eq!(c[0].severity, Severity::Critical);
        assert!(!fps.iter().any(|f| f.starts_with("access:flood")));
        let quiet = crate::collect::access::Access::default();
        quiet.record(r#"10.0.0.1 - - [x] "GET / HTTP/1.1" 500 1"#, t);
        assert!(access_conditions(&quiet.stats(5, t, 50, false), &th).is_empty());
    }

    #[test]
    fn overall_is_dragged_by_worst_dimension() {
        let d = HealthDimensions {
            cpu: 100.0,
            memory: 100.0,
            disk: 10.0,
            logs: 100.0,
            security: 100.0,
            containers: 100.0,
            database: 100.0,
        };
        assert_eq!(overall(&d), 45.0);
        let ok = HealthDimensions {
            cpu: 100.0,
            memory: 100.0,
            disk: 100.0,
            logs: 100.0,
            security: 100.0,
            containers: 100.0,
            database: 100.0,
        };
        assert_eq!(overall(&ok), 100.0);
    }

    #[test]
    fn streak_counts_both_directions() {
        assert_eq!(streak("t", true), 1);
        assert_eq!(streak("t", true), 2);
        assert_eq!(streak("t", false), -1);
        assert_eq!(streak("t", false), -2);
    }
}
