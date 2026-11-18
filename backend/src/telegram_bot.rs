//! Telegram bot: answers a few read-only commands (plus acknowledging an alert) in the chat of
//! a dashboard-configured Telegram channel with `bot_enabled`. Polls `getUpdates` every few
//! seconds; the update offset is kept in `kv` so restarts do not replay commands.
//!
//! Only messages from the configured `chat_id` are answered, and in group chats only from
//! `allowed_user_ids` when that list is set. Nothing here can change the host.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use serde_json::{Value, json};

use crate::channels::{Channel, Target, TelegramCfg};
use crate::notify::escape_html;
use crate::state::Shared;
use crate::store;

const POLL: Duration = Duration::from_secs(5);

pub fn spawn(state: &Shared) {
    let state = state.clone();
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("http client");
        // channels that failed recently (e.g. 409: another poller or a webhook) back off
        let mut backoff: HashMap<String, Instant> = HashMap::new();
        loop {
            tokio::time::sleep(POLL).await;
            for ch in bot_channels(&state).await {
                if backoff
                    .get(&ch.0.id)
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
                {
                    continue;
                }
                if let Err(e) = poll_once(&state, &http, &ch.0, &ch.1, &ch.2).await {
                    tracing::warn!("telegram bot {}: {e:#}", ch.0.name);
                    backoff.insert(ch.0.id.clone(), Instant::now());
                } else {
                    backoff.remove(&ch.0.id);
                }
            }
        }
    });
}

async fn bot_channels(state: &Shared) -> Vec<(Channel, TelegramCfg, String)> {
    crate::channels::all(state)
        .await
        .into_iter()
        .filter(|c| c.enabled)
        .filter_map(|c| match &c.target {
            Target::Telegram {
                cfg,
                token: Some(token),
            } if cfg.bot_enabled => {
                let (cfg, token) = (cfg.clone(), token.clone());
                Some((c, cfg, token))
            }
            _ => None,
        })
        .collect()
}

/// Fetches pending updates once and answers the commands among them.
pub async fn poll_once(
    state: &Shared,
    http: &reqwest::Client,
    ch: &Channel,
    cfg: &TelegramCfg,
    token: &str,
) -> Result<()> {
    let base = format!("{}/bot{}", cfg.api_base.trim_end_matches('/'), token);
    let key = format!("telegram_offset:{}", ch.id);
    let offset: i64 = store::kv_get(&state.db, &key)
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let resp = http
        .post(format!("{base}/getUpdates"))
        .json(&json!({ "offset": offset, "timeout": 0, "allowed_updates": ["message"] }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("getUpdates failed: {}", e.without_url()))?;
    if !resp.status().is_success() {
        bail!("getUpdates returned {}", resp.status());
    }
    let body: Value = resp.json().await?;
    let updates = body["result"].as_array().cloned().unwrap_or_default();
    let mut next = offset;
    for u in &updates {
        if let Some(id) = u["update_id"].as_i64() {
            next = next.max(id + 1);
        }
        let msg = &u["message"];
        let chat = msg["chat"]["id"]
            .as_i64()
            .map(|v| v.to_string())
            .or_else(|| msg["chat"]["id"].as_str().map(str::to_string));
        if chat.as_deref() != Some(cfg.chat_id.trim()) {
            continue;
        }
        let from = msg["from"]["id"].as_i64();
        if !cfg.allowed_user_ids.is_empty()
            && !from.is_some_and(|f| cfg.allowed_user_ids.contains(&f))
        {
            continue;
        }
        let Some(text) = msg["text"].as_str() else {
            continue;
        };
        if let Some(reply) = answer(state, text).await {
            let r = http
                .post(format!("{base}/sendMessage"))
                .json(&json!({ "chat_id": cfg.chat_id, "text": reply, "parse_mode": "HTML", "disable_web_page_preview": true }))
                .send()
                .await;
            if let Err(e) = r {
                tracing::warn!("telegram bot reply: {}", e.without_url());
            }
        }
    }
    if next != offset {
        store::kv_set(&state.db, &key, &next.to_string()).await?;
    }
    Ok(())
}

const HELP: &str = "可用指令：\n/status 主机状态\n/alerts 未处理的告警\n/report 最新报告摘要\n/ack 编号 确认告警\n/help 帮助";

/// Reply for a command, or None when the text is not a command we know.
pub async fn answer(state: &Shared, text: &str) -> Option<String> {
    let text = text.trim();
    if !text.starts_with('/') {
        return None;
    }
    let mut parts = text.split_whitespace();
    // "/status@MyBot" in groups
    let cmd = parts.next()?.split('@').next()?.to_ascii_lowercase();
    let arg = parts.next();
    let reply = match cmd.as_str() {
        "/start" | "/help" => HELP.to_string(),
        "/status" => status(state).await,
        "/alerts" => open_alerts(state).await,
        "/report" => latest_report(state).await,
        "/ack" => match arg.and_then(|a| a.trim_start_matches('#').parse::<i64>().ok()) {
            Some(id) => match crate::alerts::act(state, id, crate::alerts::Action::Ack).await {
                Ok(Some(a)) => format!("已确认告警 #{}：{}", a.id, escape_html(&a.title)),
                Ok(None) => format!("没有编号为 {id} 的告警"),
                Err(e) => {
                    tracing::warn!("telegram ack: {e:#}");
                    "操作失败，请查看服务日志".into()
                }
            },
            None => "用法：/ack 告警编号".into(),
        },
        _ => format!("未知指令。\n{HELP}"),
    };
    Some(reply)
}

async fn status(state: &Shared) -> String {
    match crate::api::snapshot(state).await {
        Ok(s) => {
            let mut t = format!(
                "<b>主机状态</b>\n健康评分：<b>{:.0}</b>（{}）\n模式：{}",
                s.health.score,
                if s.health.source == "ai" {
                    "AI"
                } else {
                    "规则"
                },
                escape_html(&s.mode.reason)
            );
            if let Some(h) = &s.host {
                t.push_str(&format!(
                    "\nCPU {:.0}% · 内存 {:.0}% · 磁盘 {:.0}% · 负载 {:.2}",
                    h.cpu_pct,
                    h.mem_pct(),
                    h.disk_pct(),
                    h.load1
                ));
            }
            t.push_str(&format!(
                "\n容器：{}/{} 运行中\n未处理告警：严重 {} · 警告 {}",
                s.containers.running,
                s.containers.total,
                s.alerts_open.critical,
                s.alerts_open.warning
            ));
            t
        }
        Err(e) => {
            tracing::warn!("telegram status: {e:#}");
            "暂时无法获取状态".into()
        }
    }
}

async fn open_alerts(state: &Shared) -> String {
    match crate::alerts::list(&state.db, true, 10).await {
        Ok(list) if list.is_empty() => "没有未处理的告警 ✅".into(),
        Ok(list) => {
            let mut t = format!("<b>未处理的告警（前 {} 条）</b>", list.len());
            for a in list {
                t.push_str(&format!(
                    "\n#{} [{}] {}{}",
                    a.id,
                    a.severity,
                    escape_html(&a.title),
                    if a.acked_at.is_some() {
                        "（已确认）"
                    } else {
                        ""
                    }
                ));
            }
            t
        }
        Err(e) => {
            tracing::warn!("telegram alerts: {e:#}");
            "暂时无法获取告警".into()
        }
    }
}

async fn latest_report(state: &Shared) -> String {
    match store::list_reports(&state.db, None, 1).await {
        Ok(list) => match list.into_iter().next() {
            Some(r) => format!(
                "<b>{}</b>\n健康评分：{:.0}\n{}",
                escape_html(&r.title),
                r.health_score,
                escape_html(&r.summary)
            ),
            None => "还没有报告".into(),
        },
        Err(e) => {
            tracing::warn!("telegram report: {e:#}");
            "暂时无法获取报告".into()
        }
    }
}
