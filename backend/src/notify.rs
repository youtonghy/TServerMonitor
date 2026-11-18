//! Outbound notifications over every configured channel: Telegram, email (SMTP) and signed
//! webhooks for external agents. Channels come from `channels::all`.

use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::channels::{Channel, EmailCfg, Kind, Security, Target, TelegramCfg};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::config::Severity;
use crate::model::{Alert, Diagnosis, ReportSummary, now_ms};
use crate::state::Shared;
use crate::store;

pub struct Notifier {
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

/// One notification in every format a channel may need.
pub struct Outgoing<'a> {
    /// Webhook event name and payload.
    pub event: &'a str,
    pub data: serde_json::Value,
    /// Telegram HTML; email gets a plain-text rendering of it.
    pub html: String,
    pub subject: String,
}

/// Telegram HTML -> plain text for email.
pub fn html_to_plain(s: &str) -> String {
    let re = regex::Regex::new(r"</?[a-z]+>").expect("static regex");
    re.replace_all(s, "")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Notifier {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("tsmonitor/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("http client");
        Self { http }
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    async fn send_telegram(&self, cfg: &TelegramCfg, token: &str, text: &str) -> Result<()> {
        let url = format!(
            "{}/bot{}/sendMessage",
            cfg.api_base.trim_end_matches('/'),
            token
        );
        let body = serde_json::json!({ "chat_id": cfg.chat_id, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true });
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

    async fn send_webhook(
        &self,
        url: &str,
        secret: &std::result::Result<Option<String>, String>,
        event: &str,
        data: &serde_json::Value,
    ) -> Result<()> {
        let body =
            serde_json::json!({ "event": event, "data": data, "sent_at": now_ms() }).to_string();
        let mut req = self
            .http
            .post(url)
            .header("content-type", "application/json");
        match secret {
            Ok(Some(key)) => {
                req = req.header(
                    "X-TSM-Signature",
                    format!("sha256={}", sign(key.as_bytes(), body.as_bytes())),
                );
            }
            Ok(None) => {}
            Err(e) => bail!("{e}"),
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("webhook request failed: {}", e.without_url()))?;
        if !resp.status().is_success() {
            bail!("webhook returned {}", resp.status());
        }
        Ok(())
    }

    /// Sends to one channel. `Ok(false)` = channel not usable (e.g. no token), nothing sent.
    pub async fn deliver(&self, ch: &Channel, msg: &Outgoing<'_>) -> Result<bool> {
        match &ch.target {
            Target::Telegram { cfg, token } => {
                let Some(token) = token else { return Ok(false) };
                self.send_telegram(cfg, token, &msg.html).await?;
            }
            Target::Email { cfg, password } => {
                send_email(
                    cfg,
                    password.as_deref(),
                    &msg.subject,
                    &html_to_plain(&msg.html),
                )
                .await?;
            }
            Target::Webhook { url, secret } => {
                self.send_webhook(url, secret, msg.event, &msg.data).await?;
            }
        }
        Ok(true)
    }

    /// Delivers to every channel that wants `event` and passes `filter`; logs each attempt.
    /// Returns true when at least one channel accepted it.
    async fn fan_out(
        &self,
        state: &Shared,
        event: &str,
        msg: &Outgoing<'_>,
        filter: impl Fn(&Channel) -> bool,
    ) -> bool {
        let mut any = false;
        for ch in crate::channels::all(state)
            .await
            .iter()
            .filter(|c| c.wants(event) && filter(c))
        {
            let res = self.deliver(ch, msg).await;
            let res = match res {
                Ok(false) => continue,
                Ok(true) => Ok(()),
                Err(e) => {
                    tracing::warn!("{} {event} via {}: {e:#}", ch.kind().as_str(), ch.name);
                    Err(e)
                }
            };
            any |= res.is_ok();
            let _ = store::log_notification(&state.db, ch.kind().as_str(), event, &res).await;
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

    /// Delivers an alert. Webhooks get every alert; other channels only at or above their
    /// `min_severity`. Returns true when at least one channel accepted it.
    pub async fn alert(&self, state: &Shared, a: &Alert) -> bool {
        let host = Self::host(state);
        let msg = Outgoing {
            event: "alert",
            data: serde_json::to_value(a).unwrap_or_default(),
            html: format_alert(&host, a),
            subject: format!("[{}] {} · {}", a.severity.to_uppercase(), a.title, host),
        };
        let sev = Severity::parse(&a.severity);
        self.fan_out(state, "alert", &msg, |c| {
            c.kind() == Kind::Webhook || sev >= c.min_severity
        })
        .await
    }

    pub async fn report(&self, state: &Shared, r: &ReportSummary, d: &Diagnosis) {
        let host = Self::host(state);
        let msg = Outgoing {
            event: "report",
            data: serde_json::to_value(r).unwrap_or_default(),
            html: format_report(&host, r, d),
            subject: format!("{} · {}", r.title, host),
        };
        // chat and email: the daily report and critical incidents only; webhooks get all
        let push = r.kind == "daily"
            || r.kind == "incident"
                && d.anomalies
                    .iter()
                    .any(|a| a.severity == crate::model::AlertSeverity::Critical);
        self.fan_out(state, "report", &msg, |c| c.kind() == Kind::Webhook || push)
            .await;
    }

    /// Hourly digest of warnings that were not pushed individually, for channels whose
    /// threshold is above warning.
    pub async fn warning_digest(&self, state: &Shared) -> Result<()> {
        let wants = |c: &Channel| c.kind() != Kind::Webhook && c.min_severity > Severity::Warning;
        if !crate::channels::all(state)
            .await
            .iter()
            .any(|c| c.wants("digest") && wants(c))
        {
            return Ok(());
        }
        let warnings = crate::alerts::take_unnotified_warnings(&state.db).await?;
        if warnings.is_empty() {
            return Ok(());
        }
        let host = Self::host(state);
        let mut text = format!(
            "🟠 <b>过去一小时的警告摘要（{} 条）</b>\n主机：{}",
            warnings.len(),
            escape_html(&host)
        );
        for a in warnings.iter().take(15) {
            text.push_str(&format!("\n• {}（{} 次）", escape_html(&a.title), a.count));
        }
        let msg = Outgoing {
            event: "digest",
            data: serde_json::to_value(&warnings).unwrap_or_default(),
            html: text,
            subject: format!("警告摘要（{} 条）· {host}", warnings.len()),
        };
        if self.fan_out(state, "digest", &msg, wants).await {
            crate::alerts::mark_notified(
                &state.db,
                &warnings.iter().map(|a| a.id).collect::<Vec<_>>(),
            )
            .await?;
        }
        Ok(())
    }

    /// Sends a test message to one channel, regardless of its event filter.
    pub async fn test(&self, state: &Shared, id: &str) -> Result<()> {
        let ch = crate::channels::all(state)
            .await
            .into_iter()
            .find(|c| c.id == id)
            .ok_or_else(|| crate::settings::Invalid("渠道不存在".into()))?;
        let host = Self::host(state);
        let msg = Outgoing {
            event: "test",
            data: serde_json::json!({ "message": "test" }),
            html: format!(
                "✅ <b>TServerMonitor 测试消息</b>\n主机：{}\n渠道：{}",
                escape_html(&host),
                escape_html(&ch.name)
            ),
            subject: format!("TServerMonitor 测试消息 · {host}"),
        };
        let res = match self.deliver(&ch, &msg).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(anyhow::anyhow!("渠道缺少令牌，无法发送")),
            Err(e) => Err(e),
        };
        let _ = store::log_notification(&state.db, ch.kind().as_str(), "test", &res).await;
        res
    }
}

async fn send_email(
    cfg: &EmailCfg,
    password: Option<&str>,
    subject: &str,
    body: &str,
) -> Result<()> {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    let mut b = Message::builder()
        .from(cfg.from.parse().context("invalid from address")?)
        .subject(subject);
    for t in &cfg.to {
        b = b.to(t
            .parse()
            .with_context(|| format!("invalid recipient {t}"))?);
    }
    let msg = b
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .context("building email")?;
    let builder = match cfg.security {
        Security::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?,
        Security::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?,
        Security::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host),
    };
    let mut builder = builder
        .port(cfg.port)
        .timeout(Some(Duration::from_secs(20)));
    if !cfg.username.is_empty() {
        builder = builder.credentials(Credentials::new(
            cfg.username.clone(),
            password.unwrap_or_default().to_string(),
        ));
    }
    builder
        .build()
        .send(msg)
        .await
        .map_err(|e| anyhow::anyhow!("smtp: {e}"))?;
    Ok(())
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
            acked_at: None,
            silenced_until: None,
        };
        let t = format_alert("h", &a);
        assert!(t.contains("&lt;script&gt;") && t.contains("a &amp; b") && t.contains("累计 3 次"));
    }
}
