//! Outbound notifications: Telegram (push only) and signed webhooks for external agents.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::{Config, Severity, secret};
use crate::model::{Alert, Diagnosis, ReportSummary, now_ms};
use crate::state::Shared;
use crate::store;

pub struct Notifier {
    cfg: Arc<Config>,
    http: reqwest::Client,
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn sev_icon(s: &str) -> &'static str {
    match s {
        "critical" => "🔴",
        "warning" => "🟠",
        _ => "🔵",
    }
}

pub fn format_alert(host: &str, a: &Alert) -> String {
    let mut t = format!(
        "{} <b>[{}] {}</b>\n主机：{}\n{}",
        sev_icon(&a.severity),
        escape_html(&a.severity.to_uppercase()),
        escape_html(&a.title),
        escape_html(host),
        escape_html(&a.summary)
    );
    if let Some(s) = &a.suggestion {
        t.push_str(&format!("\n\n💡 {}", escape_html(s)));
    }
    if a.count > 1 {
        t.push_str(&format!("\n（累计 {} 次）", a.count));
    }
    t
}

pub fn format_report(host: &str, r: &ReportSummary, d: &Diagnosis) -> String {
    let mut t = format!(
        "📋 <b>{}</b>\n主机：{}　健康评分：<b>{:.0}</b>（{}）\n\n{}",
        escape_html(&r.title),
        escape_html(host),
        r.health_score,
        if r.generated_by == "ai" {
            "AI"
        } else {
            "规则"
        },
        escape_html(&d.summary)
    );
    if !d.recommendations.is_empty() {
        t.push_str("\n\n<b>优先建议</b>");
        for (i, rec) in d.recommendations.iter().take(5).enumerate() {
            t.push_str(&format!("\n{}. {}", i + 1, escape_html(&rec.title)));
        }
    }
    let risks: Vec<_> = d
        .security_risks
        .iter()
        .filter(|r| r.severity >= crate::model::FindingSeverity::High)
        .collect();
    if !risks.is_empty() {
        t.push_str("\n\n<b>安全隐患</b>");
        for r in risks.iter().take(3) {
            t.push_str(&format!("\n• {}", escape_html(&r.title)));
        }
    }
    t
}

impl Notifier {
    pub fn new(cfg: Arc<Config>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("tsmonitor/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("http client");
        Self { cfg, http }
    }

    fn telegram_ready(&self) -> Option<String> {
        let t = &self.cfg.notify.telegram;
        if !t.enabled || t.chat_id.is_empty() {
            return None;
        }
        secret(&t.token_env)
    }

    async fn send_telegram(&self, token: &str, text: &str) -> Result<()> {
        let t = &self.cfg.notify.telegram;
        let url = format!(
            "{}/bot{}/sendMessage",
            t.api_base.trim_end_matches('/'),
            token
        );
        let body = serde_json::json!({ "chat_id": t.chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true });
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("telegram request failed: {}", e.without_url()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!(
                "telegram returned {status}: {}",
                crate::rules::truncate(&text, 200)
            );
        }
        Ok(())
    }

    async fn send_webhooks(&self, state: &Shared, event: &str, data: serde_json::Value) -> bool {
        let mut any = false;
        for wh in self
            .cfg
            .notify
            .webhooks
            .iter()
            .filter(|w| w.events.iter().any(|e| e == event))
        {
            let body = serde_json::json!({ "event": event, "data": data, "sent_at": now_ms() })
                .to_string();
            let res: Result<()> = async {
                let mut req = self
                    .http
                    .post(&wh.url)
                    .header("content-type", "application/json");
                if let Some(env) = &wh.secret_env {
                    let key = secret(env)
                        .with_context(|| format!("webhook secret env {env} is not set"))?;
                    req = req.header(
                        "X-TSM-Signature",
                        format!("sha256={}", sign(key.as_bytes(), body.as_bytes())),
                    );
                }
                let resp =
                    req.body(body.clone()).send().await.map_err(|e| {
                        anyhow::anyhow!("webhook request failed: {}", e.without_url())
                    })?;
                if !resp.status().is_success() {
                    bail!("webhook returned {}", resp.status());
                }
                Ok(())
            }
            .await;
            if let Err(e) = &res {
                tracing::warn!("webhook {event}: {e:#}");
            }
            any |= res.is_ok();
            let _ = store::log_notification(&state.db, "webhook", event, &res).await;
        }
        any
    }

    fn host(state: &Shared) -> String {
        state
            .read()
            .host
            .as_ref()
            .map(|h| h.hostname.clone())
            .unwrap_or_else(|| "unknown".into())
    }

    /// Delivers an alert. Telegram only gets alerts at or above `min_severity`.
    /// Returns true when at least one channel accepted it.
    pub async fn alert(&self, state: &Shared, a: &Alert) -> bool {
        let mut sent = self
            .send_webhooks(state, "alert", serde_json::to_value(a).unwrap_or_default())
            .await;
        if let Some(token) = self.telegram_ready()
            && Severity::parse(&a.severity) >= self.cfg.notify.telegram.min_severity
        {
            let res = self
                .send_telegram(&token, &format_alert(&Self::host(state), a))
                .await;
            if let Err(e) = &res {
                tracing::warn!("telegram alert: {e:#}");
            }
            sent |= res.is_ok();
            let _ = store::log_notification(&state.db, "telegram", "alert", &res).await;
        }
        sent
    }

    pub async fn report(&self, state: &Shared, r: &ReportSummary, d: &Diagnosis) {
        self.send_webhooks(state, "report", serde_json::to_value(r).unwrap_or_default())
            .await;
        let push = r.kind == "daily" && self.cfg.notify.telegram.send_daily_report
            || r.kind == "incident"
                && d.anomalies
                    .iter()
                    .any(|a| a.severity == crate::model::AlertSeverity::Critical);
        if push && let Some(token) = self.telegram_ready() {
            let res = self
                .send_telegram(&token, &format_report(&Self::host(state), r, d))
                .await;
            if let Err(e) = &res {
                tracing::warn!("telegram report: {e:#}");
            }
            let _ = store::log_notification(&state.db, "telegram", "report", &res).await;
        }
    }

    /// Hourly digest of warnings that were not pushed individually.
    pub async fn warning_digest(&self, state: &Shared) -> Result<()> {
        if !self.cfg.notify.telegram.warning_digest
            || self.cfg.notify.telegram.min_severity <= Severity::Warning
        {
            return Ok(());
        }
        let Some(token) = self.telegram_ready() else {
            return Ok(());
        };
        let warnings = crate::alerts::take_unnotified_warnings(&state.db).await?;
        if warnings.is_empty() {
            return Ok(());
        }
        let mut text = format!(
            "🟠 <b>过去一小时的警告摘要（{} 条）</b>\n主机：{}",
            warnings.len(),
            escape_html(&Self::host(state))
        );
        for a in warnings.iter().take(15) {
            text.push_str(&format!("\n• {}（{} 次）", escape_html(&a.title), a.count));
        }
        let res = self.send_telegram(&token, &text).await;
        let _ = store::log_notification(&state.db, "telegram", "digest", &res).await;
        res?;
        crate::alerts::mark_notified(
            &state.db,
            &warnings.iter().map(|a| a.id).collect::<Vec<_>>(),
        )
        .await
    }
}

pub fn sign(key: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_known_vector() {
        // RFC 4231 test case 2
        assert_eq!(
            sign(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn alert_text_is_escaped() {
        let a = Alert {
            id: 1,
            severity: "critical".into(),
            source: "x".into(),
            title: "<script>".into(),
            summary: "a & b".into(),
            suggestion: None,
            fingerprint: "f".into(),
            created_at: 0,
            last_seen: 0,
            count: 3,
            status: "open".into(),
            notified: false,
        };
        let t = format_alert("h", &a);
        assert!(t.contains("&lt;script&gt;") && t.contains("a &amp; b") && t.contains("累计 3 次"));
    }
}
