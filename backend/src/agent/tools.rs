//! Tools exposed to the model. Two kinds only:
//! 1. read-only queries over collected data, including the server-management inventory
//!    (nginx, firewall, SSH, Docker; secrets redacted);
//! 2. workspace tools (export a redacted log sample, write a script, run it in the sandbox).
//!
//! The built-in agent never changes anything itself. In conversations it gets
//! `propose_change`, which files a change request (`approvals`): a person approves it in the
//! dashboard unless the operator set that action to run automatically.
//!
//! Tool execution happens here in Rust; the Node sidecar only forwards calls.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::model::now_ms;
use crate::sandbox::Sandbox;
use crate::state::Shared;
use crate::store;

/// Tool results larger than this are cut to protect the model context.
const MAX_RESULT_CHARS: usize = 24_000;

pub struct ToolCtx<'a> {
    pub state: &'a Shared,
    pub sandbox: &'a Sandbox,
    /// Set for conversation runs: enables `propose_change`.
    pub conversation: Option<&'a str>,
    pub run_id: Option<&'a str>,
}

/// Read-only tools that are also served over MCP (the workspace/script tools are not).
pub const MCP_SHARED: &[&str] = &[
    "get_system_status",
    "analyze_logs",
    "get_access_stats",
    "get_host_metrics",
    "search_log_clusters",
    "list_containers",
    "list_package_updates",
    "get_container_logs",
    "list_log_sources",
    "get_log_rates",
    "list_ports",
    "get_db_metrics",
];

/// Conversation tools: the read-only set plus filing change requests.
pub fn chat_definitions() -> Vec<Value> {
    let mut d = definitions();
    d.push(json!({
        "name": "list_change_actions",
        "description": "列出可以申请的变更操作：名称、说明、是否需要人工批准，以及参数格式。提交 propose_change 前先看这里。",
        "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
    }));
    d.push(json!({
        "name": "propose_change",
        "description": "提交一项变更申请（你不能直接修改服务器）。需要批准的操作会先预演（给出计划或 diff），等人在面板上批准后才执行；设为自动放行的操作会立即执行。返回申请状态：pending（等待批准）、executed（已执行）、failed（失败，见 error）。一次只申请一件事。",
        "input_schema": { "type": "object", "properties": {
            "action": { "type": "string", "description": "list_change_actions 返回的操作名，如 nginx.write、firewall.add" },
            "args": { "type": "object", "description": "该操作的参数，格式见 list_change_actions" },
            "reason": { "type": "string", "description": "调用理由：为什么要改、依据的证据、预期效果（给批准人看）" }
        }, "required": ["action", "args", "reason"], "additionalProperties": false }
    }));
    d
}

pub fn definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "get_system_status",
            "description": "当前系统状态总览：主机实时指标、健康评分与各维度、运行模式、容器概况、未处理告警数、AI 状态和最新报告摘要。",
            "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
        }),
        json!({
            "name": "analyze_logs",
            "description": "日志分析汇总：各日志源的累计与当前速率、指定时间内错误最多的模板、慢日志模板，以及每小时错误数趋势。适合先用它定位问题，再用 search_log_clusters 深入。",
            "input_schema": { "type": "object", "properties": {
                "since_hours": { "type": "number", "minimum": 0.1, "maximum": 168, "description": "统计时间范围（小时），默认 1" },
                "source": { "type": "string", "description": "只看某个日志源" }
            }, "additionalProperties": false }
        }),
        json!({
            "name": "list_package_updates",
            "description": "本机待更新的软件包（apt / dnf / Homebrew）：名称、当前版本、可用版本、来源仓库、是否安全更新，以及检查时间。列表基于本机已有的软件包索引，不会刷新索引或安装任何东西。",
            "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
        }),
        json!({
            "name": "get_access_stats",
            "description": "实时访问分析（来自 nginx 访问日志）：每分钟请求数、状态码分布（2xx/3xx/4xx/5xx）、5xx 比例、流量，以及请求最多的接口和来源地址（来源地址已打码）。",
            "input_schema": { "type": "object", "properties": {
                "window_mins": { "type": "integer", "minimum": 1, "maximum": 60, "description": "统计最近多少分钟，默认 15" }
            }, "additionalProperties": false }
        }),
        json!({
            "name": "get_host_metrics",
            "description": "主机指标统计（CPU、内存、Swap、磁盘、负载、磁盘IO、网络）：每项给出最小/平均/最大/P95/最新值，以及最新的磁盘挂载点与网卡明细。",
            "input_schema": { "type": "object", "properties": {
                "range": { "type": "string", "enum": ["1h", "6h", "24h", "7d", "30d"], "description": "时间范围" }
            }, "required": ["range"], "additionalProperties": false }
        }),
        json!({
            "name": "list_containers",
            "description": "列出 Docker 容器的状态、资源占用、重启次数、OOM 与健康状态，以及最近 24 小时的容器事件（die/oom/restart）。",
            "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
        }),
        json!({
            "name": "get_container_logs",
            "description": "读取某个容器最近的标准输出/错误日志（已脱敏）。",
            "input_schema": { "type": "object", "properties": {
                "container": { "type": "string", "description": "容器名称或 ID" },
                "tail": { "type": "integer", "minimum": 1, "maximum": 500, "description": "最多返回行数，默认 200" },
                "errors_only": { "type": "boolean", "description": "只返回疑似错误行" }
            }, "required": ["container"], "additionalProperties": false }
        }),
        json!({
            "name": "list_log_sources",
            "description": "列出所有日志来源（文件与容器）及其累计行数、错误数和当前每分钟速率。",
            "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
        }),
        json!({
            "name": "search_log_clusters",
            "description": "按来源/级别/关键词检索已折叠的日志模板（相同模式的日志合并计数，已脱敏）。",
            "input_schema": { "type": "object", "properties": {
                "source": { "type": "string" },
                "level": { "type": "string", "enum": ["error", "warning", "info", "slow"] },
                "query": { "type": "string", "description": "模板中包含的关键词" },
                "since_hours": { "type": "number", "minimum": 0.1, "maximum": 2160 },
                "order": { "type": "string", "enum": ["count", "recent"] },
                "limit": { "type": "integer", "minimum": 1, "maximum": 50 }
            }, "additionalProperties": false }
        }),
        json!({
            "name": "get_log_rates",
            "description": "各日志来源的行数与错误数时间序列（按时间分桶）。",
            "input_schema": { "type": "object", "properties": {
                "range": { "type": "string", "enum": ["1h", "6h", "24h", "7d", "30d"] },
                "source": { "type": "string" }
            }, "required": ["range"], "additionalProperties": false }
        }),
        json!({
            "name": "list_findings",
            "description": "安全与配置体检发现（端口暴露、登录爆破、待装安全更新、内核参数、SSH 配置等）。",
            "input_schema": { "type": "object", "properties": {
                "include_resolved": { "type": "boolean" }
            }, "additionalProperties": false }
        }),
        json!({
            "name": "list_ports",
            "description": "主机监听端口及是否对外暴露。",
            "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
        }),
        json!({
            "name": "list_alerts",
            "description": "告警列表。",
            "input_schema": { "type": "object", "properties": {
                "status": { "type": "string", "enum": ["open", "all"] },
                "limit": { "type": "integer", "minimum": 1, "maximum": 100 }
            }, "additionalProperties": false }
        }),
        json!({
            "name": "get_db_metrics",
            "description": "数据库只读性能指标（连接数、QPS/TPS、慢查询、缓冲命中率、锁等待等）。",
            "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
        }),
        json!({
            "name": "get_report_history",
            "description": "历史分析报告摘要，用于对比趋势。",
            "input_schema": { "type": "object", "properties": {
                "kind": { "type": "string", "enum": ["hourly", "daily", "incident", "audit", "custom"] },
                "limit": { "type": "integer", "minimum": 1, "maximum": 30 }
            }, "additionalProperties": false }
        }),
        json!({
            "name": "export_log_sample",
            "description": "把某个日志来源最近的原始日志（已脱敏）导出到隔离工作区 samples/ 目录，供 Python 脚本分析。返回工作区内的相对路径。",
            "input_schema": { "type": "object", "properties": {
                "source": { "type": "string", "description": "日志来源名称（见 list_log_sources），容器来源形如 docker:<name>" },
                "max_lines": { "type": "integer", "minimum": 1, "maximum": 20000 },
                "filter_regex": { "type": "string", "description": "只保留匹配该正则的行" }
            }, "required": ["source"], "additionalProperties": false }
        }),
        json!({
            "name": "write_script",
            "description": "在隔离工作区 scripts/ 下写入 Python 脚本。脚本只能读写工作区（samples/、cache/、tmp/），无网络，无第三方包（仅标准库）。",
            "input_schema": { "type": "object", "properties": {
                "filename": { "type": "string", "pattern": "^[A-Za-z0-9_.-]+\\.py$" },
                "content": { "type": "string" }
            }, "required": ["filename", "content"], "additionalProperties": false }
        }),
        json!({
            "name": "run_python",
            "description": "在沙箱中运行 scripts/ 下的脚本，工作目录为工作区根目录。返回退出码、标准输出与标准错误（有超时和输出上限）。",
            "input_schema": { "type": "object", "properties": {
                "script": { "type": "string", "description": "如 scripts/analyze.py" },
                "args": { "type": "array", "items": { "type": "string" }, "maxItems": 16 }
            }, "required": ["script"], "additionalProperties": false }
        }),
        json!({
            "name": "get_ops_inventory",
            "description": "服务器管理面的只读信息（通过运维助手或本机只读访问获得，敏感值已打码）。what：docker_containers（容器与 compose 项目）、docker_images、nginx_sites（站点、域名、监听端口）、nginx_status（nginx 运行方式、版本、模块、运行状态、可升级版本）、nginx_versions（Docker 方式可选的 nginx 版本）、firewall（防火墙后端、规则、SSH 端口）、ssh_config（sshd 生效配置）、ssh_keys（各用户公钥指纹）、ops_jobs（最近的管理操作记录）。",
            "input_schema": { "type": "object", "properties": {
                "what": { "type": "string", "enum": ["docker_containers", "docker_images", "nginx_sites", "nginx_status", "nginx_versions", "firewall", "ssh_config", "ssh_keys", "ops_jobs"] }
            }, "required": ["what"], "additionalProperties": false }
        }),
        json!({
            "name": "get_nginx_file",
            "description": "读取一个 nginx 配置文件（相对 nginx 根目录的路径，如 sites-available/shop 或 nginx.conf），敏感值已替换为 <redacted>。适合分析配置问题与优化建议。",
            "input_schema": { "type": "object", "properties": {
                "path": { "type": "string" }
            }, "required": ["path"], "additionalProperties": false }
        }),
        json!({
            "name": "get_nginx_site",
            "description": "读取一个由面板管理的 nginx 站点（nginx_sites 中 managed = true）的设置：spec（域名、反向代理或静态目录、功能开关、SSL 方式）、证书状态、是否被手动改过，以及 sha256（修改站点时作为 base_sha256）。",
            "input_schema": { "type": "object", "properties": {
                "name": { "type": "string" }
            }, "required": ["name"], "additionalProperties": false }
        }),
        json!({
            "name": "list_workspace",
            "description": "列出隔离工作区中的文件。",
            "input_schema": { "type": "object", "properties": {}, "additionalProperties": false }
        }),
    ]
}

fn stats(values: &[f64]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    let mut v = values.to_vec();
    v.sort_by(f64::total_cmp);
    let p95 = v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)];
    let r = |x: f64| (x * 100.0).round() / 100.0;
    json!({
        "min": r(v[0]), "avg": r(v.iter().sum::<f64>() / v.len() as f64),
        "max": r(v[v.len() - 1]), "p95": r(p95), "last": r(*values.last().unwrap_or(&0.0)),
    })
}

#[derive(Deserialize)]
struct RangeArg {
    range: String,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Deserialize)]
struct ContainerLogsArg {
    container: String,
    #[serde(default)]
    tail: Option<usize>,
    #[serde(default)]
    errors_only: bool,
}

#[derive(Deserialize, Default)]
struct ClusterArg {
    source: Option<String>,
    level: Option<String>,
    query: Option<String>,
    since_hours: Option<f64>,
    order: Option<String>,
    limit: Option<i64>,
}

#[derive(Deserialize, Default)]
struct AlertArg {
    status: Option<String>,
    limit: Option<i64>,
}

#[derive(Deserialize, Default)]
struct ReportArg {
    kind: Option<String>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct ExportArg {
    source: String,
    max_lines: Option<usize>,
    filter_regex: Option<String>,
}

#[derive(Deserialize)]
struct ScriptArg {
    filename: String,
    content: String,
}

#[derive(Deserialize)]
struct RunArg {
    script: String,
    #[serde(default)]
    args: Vec<String>,
}

fn parse<T: for<'de> Deserialize<'de>>(input: &Value) -> Result<T> {
    let v = if input.is_null() {
        json!({})
    } else {
        input.clone()
    };
    serde_json::from_value(v).context("invalid tool arguments")
}

fn find_docker_id(state: &Shared, needle: &str) -> Option<String> {
    let live = state.read();
    live.containers
        .iter()
        .find(|c| c.name == needle || c.id.starts_with(needle))
        .map(|c| c.id.clone())
}

pub async fn execute(ctx: &ToolCtx<'_>, name: &str, input: &Value) -> Result<Value> {
    let state = ctx.state;
    let out = match name {
        "get_system_status" => json!(crate::api::snapshot(state).await?),
        "list_package_updates" => json!(crate::collect::packages::last()),
        "analyze_logs" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                since_hours: Option<f64>,
                source: Option<String>,
            }
            let a: A = if input.is_null() {
                A::default()
            } else {
                parse(input)?
            };
            let hours = a.since_hours.unwrap_or(1.0).clamp(0.1, 168.0);
            let since = now_ms() - (hours * 3_600_000.0) as i64;
            let top = |level| store::ClusterQuery {
                source: a.source.as_deref(),
                level: Some(level),
                since: Some(since),
                limit: 15,
                order_by_count: true,
                ..Default::default()
            };
            let errors = store::query_clusters(&state.db, &top("error")).await?;
            let warnings = store::query_clusters(&state.db, &top("warning")).await?;
            let slow = store::query_clusters(&state.db, &top("slow")).await?;
            let span = ((hours * 3_600_000.0) as i64).max(3_600_000);
            let (step, series) = store::query_log_rates(&state.db, span, now_ms()).await?;
            let trend: Vec<Value> = series
                .into_iter()
                .filter(|s| a.source.as_ref().is_none_or(|src| &s.source == src))
                .map(|s| {
                    let (lines, errors) = s.points.iter().fold((0, 0), |acc, (_, l, e)| (acc.0 + l, acc.1 + e));
                    json!({ "source": s.source, "lines": lines, "errors": errors, "points": s.points.iter().map(|(t, l, e)| json!([t, l, e])).collect::<Vec<_>>() })
                })
                .collect();
            let sources: Vec<_> = state.read().log_sources.values().cloned().collect();
            json!({
                "since_hours": hours, "bucket_secs": step, "sources": sources,
                "top_errors": errors, "top_warnings": warnings, "top_slow": slow, "rates": trend,
                "active_bursts": state.read().bursts.clone(),
            })
        }
        "get_access_stats" => {
            #[derive(Deserialize, Default)]
            #[serde(deny_unknown_fields)]
            struct A {
                window_mins: Option<i64>,
            }
            let a: A = if input.is_null() {
                A::default()
            } else {
                parse(input)?
            };
            let sources: Vec<&str> = state
                .cfg
                .logs
                .iter()
                .filter(|l| l.kind == crate::config::LogKind::NginxAccess)
                .map(|l| l.name.as_str())
                .collect();
            let stats = crate::collect::pipeline().access.stats(
                a.window_mins.unwrap_or(15),
                now_ms(),
                15,
                true,
            );
            json!({ "access_log_sources": sources, "stats": stats })
        }
        "get_host_metrics" => {
            let a: RangeArg = parse(input)?;
            let span = store::range_ms(&a.range).context("unknown range")?;
            let (step, pts) = store::query_metrics(&state.db, span, now_ms()).await?;
            let col = |f: fn(&crate::model::MetricPoint) -> f64| {
                stats(&pts.iter().map(f).collect::<Vec<_>>())
            };
            let host = state.read().host.clone();
            json!({
                "range": a.range, "samples": pts.len(), "bucket_secs": step,
                "cpu_pct": col(|p| p.cpu_pct), "mem_pct": col(|p| p.mem_pct), "swap_pct": col(|p| p.swap_pct),
                "disk_pct": col(|p| p.disk_pct), "load1": col(|p| p.load1),
                "disk_read_bps": col(|p| p.disk_read_bps), "disk_write_bps": col(|p| p.disk_write_bps),
                "net_rx_bps": col(|p| p.net_rx_bps), "net_tx_bps": col(|p| p.net_tx_bps),
                "latest": host,
            })
        }
        "list_containers" => {
            let containers = state.read().containers.clone();
            let events =
                store::recent_container_events(&state.db, now_ms() - 24 * 3_600_000, 100).await?;
            json!({ "containers": containers, "events_24h": events })
        }
        "get_container_logs" => {
            let a: ContainerLogsArg = parse(input)?;
            let id = find_docker_id(state, &a.container)
                .with_context(|| format!("container {} not found", a.container))?;
            let docker = crate::collect::docker::connect()?;
            let mut lines = crate::collect::docker::container_logs(
                &docker,
                &id,
                a.tail.unwrap_or(200).min(500),
            )
            .await?;
            if a.errors_only {
                lines.retain(|l| {
                    let t = l.get("text").and_then(Value::as_str).unwrap_or("");
                    crate::preprocess::classify(crate::config::LogKind::Docker, t).0
                        >= crate::preprocess::Level::Warning
                });
            }
            json!({ "container": a.container, "lines": lines })
        }
        "list_log_sources" => json!(
            state
                .read()
                .log_sources
                .values()
                .cloned()
                .collect::<Vec<_>>()
        ),
        "search_log_clusters" => {
            let a: ClusterArg = parse(input)?;
            let q = store::ClusterQuery {
                source: a.source.as_deref(),
                level: a.level.as_deref(),
                contains: a.query.as_deref(),
                since: a.since_hours.map(|h| now_ms() - (h * 3_600_000.0) as i64),
                limit: a.limit.unwrap_or(20).clamp(1, 50),
                order_by_count: a.order.as_deref() != Some("recent"),
            };
            json!(store::query_clusters(&state.db, &q).await?)
        }
        "get_log_rates" => {
            let a: RangeArg = parse(input)?;
            let span = store::range_ms(&a.range).context("unknown range")?;
            let (step, series) = store::query_log_rates(&state.db, span, now_ms()).await?;
            let series: Vec<Value> = series
                .into_iter()
                .filter(|s| a.source.as_ref().is_none_or(|src| &s.source == src))
                .map(|s| json!({ "source": s.source, "points": s.points.iter().map(|(t, l, e)| json!([t, l, e])).collect::<Vec<_>>() }))
                .collect();
            json!({ "bucket_secs": step, "format": "[ts_ms, lines, errors]", "series": series })
        }
        "list_findings" => {
            let include = input
                .get("include_resolved")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            json!(store::list_findings(&state.db, include).await?)
        }
        "list_ports" => json!(state.read().ports.clone()),
        "list_alerts" => {
            let a: AlertArg = parse(input)?;
            json!(
                crate::alerts::list(
                    &state.db,
                    a.status.as_deref() != Some("all"),
                    a.limit.unwrap_or(30)
                )
                .await?
            )
        }
        "get_db_metrics" => json!(state.read().dbs.clone()),
        "get_report_history" => {
            let a: ReportArg = parse(input)?;
            json!(
                store::list_reports(&state.db, a.kind.as_deref(), a.limit.unwrap_or(10).min(30))
                    .await?
            )
        }
        "export_log_sample" => {
            let a: ExportArg = parse(input)?;
            export_sample(ctx, &a).await?
        }
        "write_script" => {
            let a: ScriptArg = parse(input)?;
            let rel = ctx.sandbox.write_script(&a.filename, &a.content)?;
            json!({ "path": rel, "bytes": a.content.len() })
        }
        "run_python" => {
            let a: RunArg = parse(input)?;
            json!(ctx.sandbox.run_python(&a.script, &a.args).await?)
        }
        "list_workspace" => json!(ctx.sandbox.list()),
        "list_change_actions" => json!(crate::approvals::catalog_view(&state.db, true).await?),
        "propose_change" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                action: String,
                #[serde(default)]
                args: Value,
                reason: String,
            }
            let a: A = parse(input)?;
            let Some(conversation) = ctx.conversation else {
                bail!("只能在对话中提交变更申请");
            };
            let origin = crate::approvals::Origin {
                source: "agent",
                actor: format!("agent:{conversation}"),
                remote: None,
                conversation_id: Some(conversation.to_string()),
                run_id: ctx.run_id.map(str::to_string),
            };
            let r = crate::approvals::request(state, &a.action, a.args, &a.reason, origin).await?;
            json!({
                "request_id": r.id,
                "status": r.status,
                "summary": r.summary,
                "needs_approval": r.mode == "approve",
                "preview": r.preview,
                "result": r.result,
                "error": r.error,
                "expires_at": crate::rules::fmt_time(r.expires_at),
            })
        }
        "get_ops_inventory" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                what: String,
            }
            let a: A = parse(input)?;
            let call = match a.what.as_str() {
                "docker_containers" => "docker.containers",
                "docker_images" => "docker.images",
                "nginx_sites" => "nginx.sites",
                "nginx_status" => "nginx.status",
                "nginx_versions" => "nginx.versions",
                "firewall" => "firewall.status",
                "ssh_config" => "ssh.config",
                "ssh_keys" => "ssh.keys",
                "ops_jobs" => {
                    return Ok(cap(json!(
                        crate::ops::list_jobs(&state.db, None, 20).await?
                    )));
                }
                other => bail!("unknown inventory {other}"),
            };
            let mut v = crate::ops::read(state, call, json!({}))
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            if let Some(keys) = v["data"]["keys"].as_array_mut() {
                for k in keys {
                    if let Some(c) = k["comment"].as_str() {
                        k["comment"] = crate::preprocess::redact(c).into();
                    }
                }
            }
            v
        }
        "get_nginx_file" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                path: String,
            }
            let a: A = parse(input)?;
            let mut v = crate::ops::read(state, "nginx.file", json!({ "path": a.path }))
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            if let Some(c) = v["data"]["content"].as_str() {
                v["data"]["content"] = crate::ops::redact_config(c).into();
            }
            v
        }
        "get_nginx_site" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                name: String,
            }
            let a: A = parse(input)?;
            let mut v = crate::ops::read(state, "nginx.site_get", json!({ "name": a.name }))
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            if let Some(c) = v["data"]["spec"]["extra"].as_str() {
                v["data"]["spec"]["extra"] = crate::ops::redact_config(c).into();
            }
            v
        }
        other => bail!("unknown tool {other}"),
    };
    Ok(cap(out))
}

async fn export_sample(ctx: &ToolCtx<'_>, a: &ExportArg) -> Result<Value> {
    let max_lines = a.max_lines.unwrap_or(2000).clamp(1, 20_000);
    let filter = match &a.filter_regex {
        Some(r) => Some(
            regex::RegexBuilder::new(r)
                .size_limit(1 << 20)
                .build()
                .context("invalid filter_regex")?,
        ),
        None => None,
    };
    let raw: Vec<String> = if let Some(name) = a.source.strip_prefix("docker:") {
        let id = find_docker_id(ctx.state, name)
            .with_context(|| format!("container {name} not found"))?;
        let docker = crate::collect::docker::connect()?;
        crate::collect::docker::container_logs(&docker, &id, 2000)
            .await?
            .into_iter()
            .filter_map(|l| l.get("text").and_then(Value::as_str).map(str::to_string))
            .collect()
    } else {
        let src = ctx
            .state
            .cfg
            .logs
            .iter()
            .find(|l| l.name == a.source)
            .with_context(|| format!("unknown log source {}", a.source))?;
        let path = src.path.clone();
        // only configured log files can be read, never arbitrary paths
        tokio::task::spawn_blocking(move || {
            crate::collect::logs::read_tail(&path, 16 * 1024 * 1024)
        })
        .await??
    };
    let mut lines: Vec<String> = raw
        .into_iter()
        .filter(|l| filter.as_ref().is_none_or(|f| f.is_match(l)))
        .map(|l| crate::preprocess::redact(&l))
        .collect();
    if lines.len() > max_lines {
        lines.drain(..lines.len() - max_lines);
    }
    let safe: String = a
        .source
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let rel = format!(
        "samples/{safe}-{}.log",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    );
    let mut body = lines.join("\n");
    body.push('\n');
    ctx.sandbox
        .write_file(&rel, body.as_bytes(), 64 * 1024 * 1024)?;
    Ok(json!({ "path": rel, "lines": lines.len(), "note": "内容已脱敏；使用相对路径在脚本中读取" }))
}

fn cap(v: Value) -> Value {
    let s = v.to_string();
    if s.chars().count() <= MAX_RESULT_CHARS {
        return v;
    }
    let head: String = s.chars().take(MAX_RESULT_CHARS).collect();
    json!({ "truncated": true, "original_chars": s.chars().count(), "partial_json": head, "hint": "结果过长已截断，请缩小查询范围或使用 limit 参数" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tool_has_object_schema() {
        let defs = definitions();
        assert!(defs.len() >= 14);
        for d in defs {
            assert_eq!(d["input_schema"]["type"], "object", "{}", d["name"]);
            assert!(d["description"].as_str().is_some_and(|s| !s.is_empty()));
        }
    }

    #[test]
    fn stats_are_computed() {
        let s = stats(&[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(s["min"], 1.0);
        assert_eq!(s["max"], 4.0);
        assert_eq!(s["last"], 4.0);
        assert_eq!(s["avg"], 2.5);
    }

    #[test]
    fn big_results_are_capped() {
        let v = cap(json!({ "x": "a".repeat(MAX_RESULT_CHARS * 2) }));
        assert_eq!(v["truncated"], true);
    }
}
