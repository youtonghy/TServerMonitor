//! Notification channels: TOML `[notify.telegram]` / `[[notify.webhooks]]` (read-only) plus
//! channels added from the dashboard (`notify_channels`). Secrets (bot token, SMTP password,
//! webhook HMAC key) are encrypted with the same master key as provider keys.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::{Severity, secret};
use crate::model::now_ms;
use crate::settings::{Invalid, Settings, validate_base_url};
use crate::state::Shared;
use crate::store::Db;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Telegram,
    Email,
    Webhook,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Telegram => "telegram",
            Kind::Email => "email",
            Kind::Webhook => "webhook",
        }
    }
}

fn default_api_base() -> String {
    "https://api.telegram.org".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramCfg {
    pub chat_id: String,
    #[serde(default = "default_api_base")]
    pub api_base: String,
    /// Answer read-only commands sent to the bot in `chat_id`.
    #[serde(default)]
    pub bot_enabled: bool,
    /// In group chats only these Telegram user ids may issue commands (empty = anyone in the chat).
    #[serde(default)]
    pub allowed_user_ids: Vec<i64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    Starttls,
    Tls,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailCfg {
    pub host: String,
    pub port: u16,
    pub security: Security,
    #[serde(default)]
    pub username: String,
    pub from: String,
    pub to: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookCfg {
    pub url: String,
}

#[derive(Debug, Clone)]
pub enum Target {
    Telegram {
        cfg: TelegramCfg,
        token: Option<String>,
    },
    Email {
        cfg: EmailCfg,
        password: Option<String>,
    },
    /// `secret`: Err = configured env var missing (TOML), reported when sending.
    Webhook {
        url: String,
        secret: std::result::Result<Option<String>, String>,
    },
}

#[derive(Debug, Clone)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub source: &'static str,
    pub enabled: bool,
    pub min_severity: Severity,
    pub events: Vec<String>,
    pub target: Target,
}

impl Channel {
    pub fn kind(&self) -> Kind {
        match self.target {
            Target::Telegram { .. } => Kind::Telegram,
            Target::Email { .. } => Kind::Email,
            Target::Webhook { .. } => Kind::Webhook,
        }
    }
    pub fn wants(&self, event: &str) -> bool {
        self.enabled && self.events.iter().any(|e| e == event)
    }
}

/// API view without secrets.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelView {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub source: &'static str,
    pub enabled: bool,
    pub min_severity: Severity,
    pub events: Vec<String>,
    pub config: serde_json::Value,
    pub has_secret: bool,
}

impl From<&Channel> for ChannelView {
    fn from(c: &Channel) -> Self {
        let (config, has_secret) = match &c.target {
            Target::Telegram { cfg, token } => (serde_json::to_value(cfg), token.is_some()),
            Target::Email { cfg, password } => (serde_json::to_value(cfg), password.is_some()),
            Target::Webhook { url, secret } => (
                Ok(serde_json::json!({ "url": url })),
                matches!(secret, Ok(Some(_))),
            ),
        };
        Self {
            id: c.id.clone(),
            name: c.name.clone(),
            kind: c.kind(),
            source: c.source,
            enabled: c.enabled,
            min_severity: c.min_severity,
            events: c.events.clone(),
            config: config.unwrap_or_default(),
            has_secret,
        }
    }
}

fn config_channels(state: &Shared) -> Vec<Channel> {
    let n = &state.cfg.notify;
    let mut out = Vec::new();
    let t = &n.telegram;
    if t.enabled && !t.chat_id.is_empty() {
        let mut events = vec!["alert".to_string()];
        if t.send_daily_report {
            events.push("report".into());
        }
        if t.warning_digest {
            events.push("digest".into());
        }
        out.push(Channel {
            id: "config:telegram".into(),
            name: "Telegram（配置文件）".into(),
            source: "config",
            enabled: true,
            min_severity: t.min_severity,
            events,
            target: Target::Telegram {
                cfg: TelegramCfg {
                    chat_id: t.chat_id.clone(),
                    api_base: t.api_base.clone(),
                    bot_enabled: false,
                    allowed_user_ids: Vec::new(),
                },
                token: secret(&t.token_env),
            },
        });
    }
    for (i, w) in n.webhooks.iter().enumerate() {
        let secret = match &w.secret_env {
            None => Ok(None),
            Some(env) => secret(env)
                .map(Some)
                .ok_or_else(|| format!("webhook secret env {env} is not set")),
        };
        out.push(Channel {
            id: format!("config:webhook:{i}"),
            name: format!("Webhook {}（配置文件）", i + 1),
            source: "config",
            enabled: true,
            // webhooks always received every alert
            min_severity: Severity::Info,
            events: w.events.clone(),
            target: Target::Webhook {
                url: w.url.clone(),
                secret,
            },
        });
    }
    out
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    kind: String,
    name: String,
    enabled: bool,
    min_severity: String,
    events: String,
    config: String,
    secret_cipher: Option<String>,
}

fn row_to_channel(settings: &Settings, r: Row) -> Option<Channel> {
    let secret = r
        .secret_cipher
        .as_deref()
        .and_then(|c| match settings.decrypt_key(c) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!("channel {}: {e:#}", r.id);
                None
            }
        });
    let target = match r.kind.as_str() {
        "telegram" => Target::Telegram {
            cfg: serde_json::from_str(&r.config).ok()?,
            token: secret,
        },
        "email" => Target::Email {
            cfg: serde_json::from_str(&r.config).ok()?,
            password: secret,
        },
        "webhook" => Target::Webhook {
            url: serde_json::from_str::<WebhookCfg>(&r.config).ok()?.url,
            secret: Ok(secret),
        },
        _ => return None,
    };
    Some(Channel {
        id: r.id,
        name: r.name,
        source: "db",
        enabled: r.enabled,
        min_severity: Severity::parse(&r.min_severity),
        events: serde_json::from_str(&r.events).unwrap_or_default(),
        target,
    })
}

/// Every channel, TOML first. DB failures are logged so alerting keeps working.
pub async fn all(state: &Shared) -> Vec<Channel> {
    let mut out = config_channels(state);
    match sqlx::query_as::<_, Row>(
        "SELECT id, kind, name, enabled, min_severity, events, config, secret_cipher FROM notify_channels ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => out.extend(
            rows.into_iter()
                .filter_map(|r| row_to_channel(&state.settings, r)),
        ),
        Err(e) => tracing::warn!("loading notification channels: {e:#}"),
    }
    out
}

// ---------------------------------------------------------------- CRUD

#[derive(Debug, Deserialize)]
pub struct ChannelInput {
    pub kind: Option<Kind>,
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub min_severity: Option<Severity>,
    pub events: Option<Vec<String>>,
    pub config: Option<serde_json::Value>,
    /// Write-only; empty string clears it.
    pub secret: Option<String>,
}

fn invalid(msg: impl Into<String>) -> anyhow::Error {
    Invalid(msg.into()).into()
}

/// Validates and normalizes the per-kind config JSON.
fn check_config(kind: Kind, v: &serde_json::Value) -> Result<serde_json::Value> {
    match kind {
        Kind::Telegram => {
            let c: TelegramCfg = serde_json::from_value(v.clone())
                .map_err(|e| invalid(format!("Telegram 配置不正确：{e}")))?;
            if c.chat_id.trim().is_empty() || c.chat_id.len() > 64 {
                return Err(invalid("chat_id 不能为空"));
            }
            validate_base_url(&c.api_base)?;
            Ok(serde_json::to_value(c)?)
        }
        Kind::Email => {
            let c: EmailCfg = serde_json::from_value(v.clone())
                .map_err(|e| invalid(format!("邮件配置不正确：{e}")))?;
            if c.host.trim().is_empty() || c.host.contains(['/', ' ']) {
                return Err(invalid("SMTP 服务器地址不正确"));
            }
            if c.port == 0 {
                return Err(invalid("端口不正确"));
            }
            c.from
                .parse::<lettre::message::Mailbox>()
                .map_err(|_| invalid("发件人地址不正确"))?;
            if c.to.is_empty() || c.to.len() > 20 {
                return Err(invalid("收件人需要 1 到 20 个"));
            }
            for t in &c.to {
                t.parse::<lettre::message::Mailbox>()
                    .map_err(|_| invalid(format!("收件人地址不正确：{t}")))?;
            }
            Ok(serde_json::to_value(c)?)
        }
        Kind::Webhook => {
            let c: WebhookCfg = serde_json::from_value(v.clone())
                .map_err(|e| invalid(format!("Webhook 配置不正确：{e}")))?;
            validate_base_url(&c.url)?;
            Ok(serde_json::to_value(c)?)
        }
    }
}

fn check_events(events: &[String]) -> Result<()> {
    if events.is_empty() {
        return Err(invalid("至少选择一种通知事件"));
    }
    if events
        .iter()
        .any(|e| !matches!(e.as_str(), "alert" | "report" | "digest"))
    {
        return Err(invalid("事件只能是 alert、report、digest"));
    }
    Ok(())
}

fn encrypt(settings: &Settings, s: &str) -> Result<Option<String>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if s.len() > 4096 || s.chars().any(char::is_control) {
        return Err(invalid("密钥格式不合法"));
    }
    settings
        .encrypt_key(s)
        .map(Some)
        .map_err(|e| invalid(format!("{e:#}")))
}

pub async fn create(settings: &Settings, db: &Db, inp: ChannelInput) -> Result<String> {
    let kind = inp.kind.ok_or_else(|| invalid("缺少渠道类型"))?;
    let name = inp.name.unwrap_or_default();
    if name.trim().is_empty() || name.chars().count() > 64 {
        return Err(invalid("名称不能为空，且不超过 64 个字符"));
    }
    let config = check_config(kind, &inp.config.unwrap_or_default())?;
    let events = inp
        .events
        .unwrap_or_else(|| vec!["alert".into(), "digest".into()]);
    check_events(&events)?;
    let cipher = match inp.secret.as_deref() {
        Some(s) => encrypt(settings, s)?,
        None => None,
    };
    let id = format!("n_{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
    let now = now_ms();
    sqlx::query("INSERT INTO notify_channels (id, kind, name, enabled, min_severity, events, config, secret_cipher, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(kind.as_str())
        .bind(name.trim())
        .bind(inp.enabled.unwrap_or(true))
        .bind(inp.min_severity.unwrap_or(Severity::Critical).as_str())
        .bind(serde_json::to_string(&events)?)
        .bind(config.to_string())
        .bind(cipher)
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn update(settings: &Settings, db: &Db, id: &str, inp: ChannelInput) -> Result<bool> {
    let Some(cur) = sqlx::query_as::<_, Row>(
        "SELECT id, kind, name, enabled, min_severity, events, config, secret_cipher FROM notify_channels WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?
    else {
        return Ok(false);
    };
    let kind: Kind = serde_json::from_value(serde_json::Value::String(cur.kind.clone()))?;
    if inp.kind.is_some_and(|k| k != kind) {
        return Err(invalid("不能修改渠道类型"));
    }
    let name = inp.name.unwrap_or(cur.name);
    if name.trim().is_empty() || name.chars().count() > 64 {
        return Err(invalid("名称不能为空，且不超过 64 个字符"));
    }
    let old_config: serde_json::Value = serde_json::from_str(&cur.config)?;
    let config = match inp.config {
        Some(c) => check_config(kind, &c)?,
        None => old_config.clone(),
    };
    // a stored secret must not silently follow the channel to a different destination
    let destination = |v: &serde_json::Value| match kind {
        Kind::Telegram => v["api_base"].clone(),
        Kind::Email => serde_json::json!([v["host"], v["port"], v["username"]]),
        Kind::Webhook => v["url"].clone(),
    };
    if destination(&config) != destination(&old_config)
        && cur.secret_cipher.is_some()
        && inp.secret.is_none()
    {
        return Err(invalid("修改了目标地址，必须重新填写密钥/密码"));
    }
    let events = match inp.events {
        Some(e) => {
            check_events(&e)?;
            e
        }
        None => serde_json::from_str(&cur.events)?,
    };
    let cipher = match inp.secret.as_deref() {
        Some(s) => encrypt(settings, s)?,
        None => cur.secret_cipher,
    };
    sqlx::query("UPDATE notify_channels SET name = ?, enabled = ?, min_severity = ?, events = ?, config = ?, secret_cipher = ?, updated_at = ? WHERE id = ?")
        .bind(name.trim())
        .bind(inp.enabled.unwrap_or(cur.enabled))
        .bind(
            inp.min_severity
                .map(Severity::as_str)
                .unwrap_or(&cur.min_severity),
        )
        .bind(serde_json::to_string(&events)?)
        .bind(config.to_string())
        .bind(cipher)
        .bind(now_ms())
        .bind(id)
        .execute(db)
        .await?;
    Ok(true)
}

pub async fn delete(db: &Db, id: &str) -> Result<bool> {
    Ok(sqlx::query("DELETE FROM notify_channels WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?
        .rows_affected()
        > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn email_channel_crud_and_secret_rules() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.storage.data_dir = dir.path().to_path_buf();
        let settings = Settings::new(std::sync::Arc::new(cfg));
        settings.set_file_key_allowed(true);
        let db = crate::store::open_memory().await;
        let config = serde_json::json!({ "host": "smtp.example.com", "port": 587, "security": "starttls", "username": "u", "from": "监控 <mon@example.com>", "to": ["ops@example.com"] });
        let id = create(
            &settings,
            &db,
            ChannelInput {
                kind: Some(Kind::Email),
                name: Some("运维邮箱".into()),
                enabled: None,
                min_severity: None,
                events: None,
                config: Some(config.clone()),
                secret: Some("pw".into()),
            },
        )
        .await
        .unwrap();
        let mut moved = config.clone();
        moved["host"] = "evil.example.com".into();
        let err = update(
            &settings,
            &db,
            &id,
            ChannelInput {
                kind: None,
                name: None,
                enabled: None,
                min_severity: None,
                events: None,
                config: Some(moved),
                secret: None,
            },
        )
        .await
        .unwrap_err();
        assert!(err.downcast_ref::<Invalid>().is_some());
        let mut bad = config;
        bad["to"] = serde_json::json!(["not an address"]);
        assert!(check_config(Kind::Email, &bad).is_err());
        assert!(delete(&db, &id).await.unwrap());
    }
}
