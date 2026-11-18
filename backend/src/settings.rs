//! Runtime settings editable from the dashboard, layered over the immutable TOML config.
//!
//! * Providers: TOML `[ai.profiles.*]` stay read-only; providers added in the UI live in the
//!   `providers` table. Their API keys are encrypted with XChaCha20-Poly1305 under a master
//!   key from `TSM_SECRET_KEY` (preferred) or `<data_dir>/secret.key`. Keys are write-only over
//!   the API and reach the sidecar only through its environment.
//! * Routing: task kind -> provider + model + reasoning effort (`task_routes`). Kinds without a
//!   row fall back to the `default` row, then to TOML `[ai.routing]` / `[ai.profiles.default]`.
//!
//! Every write reloads the snapshot and bumps `generation`, which makes the agent respawn its
//! sidecar with fresh environment before the next run.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{ApiFormat, AuthStyle, Config, secret};
use crate::model::now_ms;
use crate::store::Db;

pub const SECRET_KEY_ENV: &str = "TSM_SECRET_KEY";

/// Task kinds that can be routed to a model. `default` is the fallback for all others.
pub const TASK_KINDS: &[(&str, &str)] = &[
    ("default", "默认"),
    ("hourly", "小时巡检"),
    ("daily", "每日运维简报"),
    ("incident", "异常事件分析"),
    ("audit", "深度审计"),
    ("chat", "对话"),
    ("log_scan", "日志扫描"),
    ("security_check", "安全体检"),
    ("package_advice", "包更新建议"),
    ("prompt_gen", "提示词生成"),
];

/// Reasoning effort levels understood by the sidecar (AI SDK `reasoning`). Empty = provider default.
pub const EFFORTS: &[&str] = &[
    "", "none", "minimal", "low", "medium", "high", "xhigh", "max",
];

#[derive(Debug, Clone, Serialize)]
pub struct ProviderView {
    pub id: String,
    pub name: String,
    /// "db" (editable) or "config" (TOML, read-only)
    pub source: &'static str,
    pub api_format: ApiFormat,
    pub base_url: String,
    pub auth: AuthStyle,
    pub default_model: String,
    pub has_key: bool,
    /// Env var holding the key (TOML providers only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_env: Option<String>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    pub kind: String,
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub effort: String,
}

/// Everything the agent needs to call a model for one task.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedModel {
    pub provider: String,
    pub source: &'static str,
    pub api_format: ApiFormat,
    pub base_url: String,
    pub model: String,
    pub auth: AuthStyle,
    pub effort: String,
    #[serde(skip)]
    pub key_env: String,
    #[serde(skip)]
    pub has_key: bool,
}

#[derive(Debug, Default)]
pub struct Snapshot {
    pub providers: Vec<ProviderView>,
    pub routes: BTreeMap<String, Route>,
}

pub struct Settings {
    cfg: Arc<Config>,
    snap: RwLock<Arc<Snapshot>>,
    generation: AtomicU64,
    /// The key file is only trusted when analysis scripts cannot read the data dir.
    file_key_allowed: AtomicBool,
}

#[derive(sqlx::FromRow)]
struct ProviderRow {
    id: String,
    name: String,
    api_format: String,
    base_url: String,
    auth: String,
    default_model: String,
    key_cipher: Option<String>,
    updated_at: i64,
}

fn parse_format(s: &str) -> ApiFormat {
    if s == "messages" {
        ApiFormat::Messages
    } else {
        ApiFormat::Responses
    }
}

pub fn format_str(f: ApiFormat) -> &'static str {
    match f {
        ApiFormat::Responses => "responses",
        ApiFormat::Messages => "messages",
    }
}

fn parse_auth(s: &str) -> AuthStyle {
    if s == "bearer" {
        AuthStyle::Bearer
    } else {
        AuthStyle::ApiKey
    }
}

pub fn auth_str(a: AuthStyle) -> &'static str {
    match a {
        AuthStyle::ApiKey => "api_key",
        AuthStyle::Bearer => "bearer",
    }
}

/// Env var name under which a DB provider's key is handed to the sidecar.
pub fn provider_key_env(id: &str) -> String {
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("TSM_PROVIDER_{safe}_KEY")
}

impl Settings {
    pub fn new(cfg: Arc<Config>) -> Self {
        let s = Self {
            cfg,
            snap: RwLock::new(Arc::new(Snapshot::default())),
            generation: AtomicU64::new(0),
            file_key_allowed: AtomicBool::new(false),
        };
        // TOML providers are visible even before the first reload
        *s.snap.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(Snapshot {
            providers: s.config_providers(),
            routes: BTreeMap::new(),
        });
        s
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snap.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn set_file_key_allowed(&self, allowed: bool) {
        self.file_key_allowed.store(allowed, Ordering::SeqCst);
    }

    fn config_providers(&self) -> Vec<ProviderView> {
        self.cfg
            .ai
            .profiles
            .iter()
            .map(|(name, p)| ProviderView {
                id: name.clone(),
                name: name.clone(),
                source: "config",
                api_format: p.api_format,
                base_url: p.base_url.clone(),
                auth: p.auth,
                default_model: p.model.clone(),
                has_key: secret(&p.api_key_env).is_some(),
                key_env: Some(p.api_key_env.clone()),
                updated_at: None,
            })
            .collect()
    }

    pub async fn reload(&self, db: &Db) -> Result<()> {
        let rows = sqlx::query_as::<_, ProviderRow>(
            "SELECT id, name, api_format, base_url, auth, default_model, key_cipher, updated_at FROM providers ORDER BY created_at",
        )
        .fetch_all(db)
        .await?;
        let mut providers: Vec<ProviderView> = rows
            .into_iter()
            .map(|r| ProviderView {
                id: r.id,
                name: r.name,
                source: "db",
                api_format: parse_format(&r.api_format),
                base_url: r.base_url,
                auth: parse_auth(&r.auth),
                default_model: r.default_model,
                has_key: r.key_cipher.is_some(),
                key_env: None,
                updated_at: Some(r.updated_at),
            })
            .collect();
        providers.extend(self.config_providers());
        let routes = sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT kind, provider, model, effort FROM task_routes",
        )
        .fetch_all(db)
        .await?
        .into_iter()
        .map(|(kind, provider, model, effort)| {
            (
                kind.clone(),
                Route {
                    kind,
                    provider,
                    model,
                    effort,
                },
            )
        })
        .collect();
        *self.snap.write().unwrap_or_else(|e| e.into_inner()) =
            Arc::new(Snapshot { providers, routes });
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Model for a task kind, or None when nothing is configured.
    pub fn resolve(&self, kind: &str) -> Option<ResolvedModel> {
        let snap = self.snapshot();
        let route = snap.routes.get(kind).or_else(|| snap.routes.get("default"));
        let (provider, model, effort) = match route {
            Some(r) => (r.provider.clone(), r.model.clone(), r.effort.clone()),
            None => {
                // legacy TOML routing
                let (name, _) = self.cfg.ai.profile_for(kind)?;
                (name.to_string(), String::new(), String::new())
            }
        };
        let p = snap.providers.iter().find(|p| p.id == provider)?;
        let model = if model.is_empty() {
            p.default_model.clone()
        } else {
            model
        };
        if model.is_empty() {
            return None;
        }
        let key_env = match &p.key_env {
            Some(env) => env.clone(),
            None => provider_key_env(&p.id),
        };
        Some(ResolvedModel {
            provider: p.id.clone(),
            source: p.source,
            api_format: p.api_format,
            base_url: p.base_url.clone(),
            model,
            auth: p.auth,
            effort,
            has_key: if p.source == "config" {
                secret(&key_env).is_some()
            } else {
                p.has_key
            },
            key_env,
        })
    }

    // ------------------------------------------------------------ key storage

    /// Where provider keys would be stored: "env", "file", or "unavailable".
    pub fn key_storage(&self) -> &'static str {
        if secret(SECRET_KEY_ENV).is_some() {
            "env"
        } else if self.file_key_allowed.load(Ordering::SeqCst) {
            "file"
        } else {
            "unavailable"
        }
    }

    fn key_file(&self) -> PathBuf {
        self.cfg.storage.data_dir.join("secret.key")
    }

    fn cipher(&self, create: bool) -> Result<XChaCha20Poly1305> {
        let material: Vec<u8> = if let Some(k) = secret(SECRET_KEY_ENV) {
            k.into_bytes()
        } else if self.file_key_allowed.load(Ordering::SeqCst) {
            let path = self.key_file();
            match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                    let mut k = [0u8; 32];
                    getrandom::fill(&mut k).map_err(|e| anyhow!("rng: {e}"))?;
                    let hex = hex::encode(k);
                    write_private(&path, hex.as_bytes())?;
                    hex.into_bytes()
                }
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            }
        } else {
            bail!(
                "密钥存储不可用：请设置环境变量 {SECRET_KEY_ENV}（本机沙箱无法隔离数据目录，不能使用密钥文件）"
            );
        };
        // any length of material -> 32-byte key
        let key = Sha256::digest(&material);
        XChaCha20Poly1305::new_from_slice(&key).map_err(|_| anyhow!("invalid key length"))
    }

    pub fn encrypt_key(&self, plain: &str) -> Result<String> {
        let cipher = self.cipher(true)?;
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| anyhow!("rng: {e}"))?;
        let ct = cipher
            .encrypt(&XNonce::from(nonce), plain.as_bytes())
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut out = nonce.to_vec();
        out.extend(ct);
        Ok(B64.encode(out))
    }

    pub fn decrypt_key(&self, stored: &str) -> Result<String> {
        let raw = B64.decode(stored).context("stored key is not base64")?;
        if raw.len() < 24 + 16 {
            bail!("stored key is truncated");
        }
        let (nonce, ct) = raw.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().expect("split at 24");
        let plain = self
            .cipher(false)?
            .decrypt(&XNonce::from(nonce), ct)
            .map_err(|_| anyhow!("密钥无法解密（主密钥已变化？请重新填写该 Provider 的密钥）"))?;
        String::from_utf8(plain).context("stored key is not UTF-8")
    }

    /// `(env name, key)` for every DB provider whose key decrypts; failures are logged.
    pub async fn provider_env(&self, db: &Db) -> Vec<(String, String)> {
        let rows = match sqlx::query_as::<_, (String, String)>(
            "SELECT id, key_cipher FROM providers WHERE key_cipher IS NOT NULL",
        )
        .fetch_all(db)
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("loading provider keys: {e:#}");
                return Vec::new();
            }
        };
        rows.into_iter()
            .filter_map(|(id, c)| match self.decrypt_key(&c) {
                Ok(k) => Some((provider_key_env(&id), k)),
                Err(e) => {
                    tracing::warn!("provider {id}: {e:#}");
                    None
                }
            })
            .collect()
    }

    /// Plain key of a DB provider (used for listing models).
    pub async fn provider_key(&self, db: &Db, id: &str) -> Result<Option<String>> {
        if let Some(p) = self.cfg.ai.profiles.get(id) {
            return Ok(secret(&p.api_key_env));
        }
        let c: Option<Option<String>> =
            sqlx::query_scalar("SELECT key_cipher FROM providers WHERE id = ?")
                .bind(id)
                .fetch_optional(db)
                .await?;
        match c.flatten() {
            Some(c) => self.decrypt_key(&c).map(Some),
            None => Ok(None),
        }
    }
}

fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

// ---------------------------------------------------------------- provider CRUD

#[derive(Debug, Deserialize)]
pub struct ProviderInput {
    pub name: Option<String>,
    pub api_format: Option<ApiFormat>,
    pub base_url: Option<String>,
    pub auth: Option<AuthStyle>,
    pub default_model: Option<String>,
    /// Write-only. Empty string clears the stored key.
    pub api_key: Option<String>,
}

/// Validation failures that should reach the user as 400.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Invalid(pub String);

fn invalid(msg: impl Into<String>) -> anyhow::Error {
    Invalid(msg.into()).into()
}

pub fn validate_base_url(url: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(url.trim()).map_err(|_| invalid("base_url 不是合法的 URL"))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(invalid("base_url 只支持 http/https"));
    }
    if u.host_str().is_none() {
        return Err(invalid("base_url 缺少主机名"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(invalid("base_url 不能包含账号密码，请填写到密钥字段"));
    }
    if let Some(url::Host::Ipv4(ip)) = u.host().map(|h| h.to_owned()) {
        check_ip(IpAddr::V4(ip))?;
    }
    if let Some(url::Host::Ipv6(ip)) = u.host().map(|h| h.to_owned()) {
        check_ip(IpAddr::V6(ip))?;
    }
    Ok(u)
}

/// Loopback and private ranges stay allowed (local gateways); link-local covers cloud metadata.
fn check_ip(ip: IpAddr) -> Result<()> {
    let bad = match ip {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80,
    };
    if bad {
        return Err(invalid("base_url 指向链路本地或保留地址，已拒绝"));
    }
    Ok(())
}

fn clean_name(s: &str) -> Result<String> {
    let s = s.trim();
    if s.is_empty() || s.chars().count() > 64 {
        return Err(invalid("名称不能为空，且不超过 64 个字符"));
    }
    Ok(s.to_string())
}

fn clean_model(s: &str) -> Result<String> {
    let s = s.trim();
    if s.len() > 200 || s.chars().any(char::is_control) {
        return Err(invalid("模型名不合法"));
    }
    Ok(s.to_string())
}

fn clean_key(s: &str) -> Result<String> {
    let s = s.trim();
    if s.len() > 4096 || s.chars().any(char::is_control) {
        return Err(invalid("密钥格式不合法"));
    }
    Ok(s.to_string())
}

pub async fn create_provider(settings: &Settings, db: &Db, inp: ProviderInput) -> Result<String> {
    let name = clean_name(inp.name.as_deref().unwrap_or(""))?;
    let format = inp.api_format.ok_or_else(|| invalid("缺少 api_format"))?;
    let base = validate_base_url(inp.base_url.as_deref().unwrap_or(""))?;
    let model = clean_model(inp.default_model.as_deref().unwrap_or(""))?;
    let cipher = match inp.api_key.as_deref().map(clean_key).transpose()? {
        Some(k) if !k.is_empty() => Some(
            settings
                .encrypt_key(&k)
                .map_err(|e| invalid(format!("{e:#}")))?,
        ),
        _ => None,
    };
    let id = format!("p{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let now = now_ms();
    sqlx::query("INSERT INTO providers (id, name, api_format, base_url, auth, default_model, key_cipher, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(&name)
        .bind(format_str(format))
        .bind(base.as_str().trim_end_matches('/'))
        .bind(auth_str(inp.auth.unwrap_or_default()))
        .bind(&model)
        .bind(cipher)
        .bind(now)
        .bind(now)
        .execute(db)
        .await?;
    settings.reload(db).await?;
    Ok(id)
}

pub async fn update_provider(
    settings: &Settings,
    db: &Db,
    id: &str,
    inp: ProviderInput,
) -> Result<bool> {
    let Some(cur) = sqlx::query_as::<_, ProviderRow>(
        "SELECT id, name, api_format, base_url, auth, default_model, key_cipher, updated_at FROM providers WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?
    else {
        return Ok(false);
    };
    let name = match &inp.name {
        Some(n) => clean_name(n)?,
        None => cur.name,
    };
    let base = match &inp.base_url {
        Some(u) => validate_base_url(u)?
            .as_str()
            .trim_end_matches('/')
            .to_string(),
        None => cur.base_url.clone(),
    };
    let key = inp.api_key.as_deref().map(clean_key).transpose()?;
    // a stored key must not silently follow the provider to a different server
    if base != cur.base_url && cur.key_cipher.is_some() && key.is_none() {
        return Err(invalid("修改 base_url 时必须重新填写密钥"));
    }
    let cipher = match key {
        Some(k) if k.is_empty() => None,
        Some(k) => Some(
            settings
                .encrypt_key(&k)
                .map_err(|e| invalid(format!("{e:#}")))?,
        ),
        None => cur.key_cipher,
    };
    let model = match &inp.default_model {
        Some(m) => clean_model(m)?,
        None => cur.default_model,
    };
    sqlx::query("UPDATE providers SET name = ?, api_format = ?, base_url = ?, auth = ?, default_model = ?, key_cipher = ?, updated_at = ? WHERE id = ?")
        .bind(name)
        .bind(inp.api_format.map(format_str).unwrap_or(&cur.api_format))
        .bind(base)
        .bind(inp.auth.map(auth_str).unwrap_or(&cur.auth))
        .bind(model)
        .bind(cipher)
        .bind(now_ms())
        .bind(id)
        .execute(db)
        .await?;
    settings.reload(db).await?;
    Ok(true)
}

pub async fn delete_provider(settings: &Settings, db: &Db, id: &str) -> Result<bool> {
    let n = sqlx::query("DELETE FROM providers WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM task_routes WHERE provider = ?")
        .bind(id)
        .execute(db)
        .await?;
    settings.reload(db).await?;
    Ok(n > 0)
}

pub async fn replace_routes(settings: &Settings, db: &Db, routes: &[Route]) -> Result<()> {
    let snap = settings.snapshot();
    for r in routes {
        if !TASK_KINDS.iter().any(|(k, _)| *k == r.kind) {
            return Err(invalid(format!("未知任务类型 {}", r.kind)));
        }
        if !snap.providers.iter().any(|p| p.id == r.provider) {
            return Err(invalid(format!("未知 Provider {}", r.provider)));
        }
        if !EFFORTS.contains(&r.effort.as_str()) {
            return Err(invalid(format!("未知思考强度 {}", r.effort)));
        }
        clean_model(&r.model)?;
    }
    let mut tx = db.begin().await?;
    sqlx::query("DELETE FROM task_routes")
        .execute(&mut *tx)
        .await?;
    for r in routes {
        sqlx::query("INSERT INTO task_routes (kind, provider, model, effort, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&r.kind)
            .bind(&r.provider)
            .bind(r.model.trim())
            .bind(&r.effort)
            .bind(now_ms())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    settings.reload(db).await
}

// ---------------------------------------------------------------- model listing

const MODELS_BODY_CAP: usize = 2 * 1024 * 1024;

/// Lists model ids from `{base_url}/models` in the given wire format.
pub async fn fetch_models(
    format: ApiFormat,
    base_url: &str,
    auth: AuthStyle,
    key: Option<&str>,
) -> Result<Vec<String>> {
    let base = validate_base_url(base_url)?;
    // reject hostnames resolving to link-local (cloud metadata) addresses
    if let Some(host) = base.host_str()
        && base
            .host()
            .is_some_and(|h| matches!(h, url::Host::Domain(_)))
    {
        let port = base.port_or_known_default().unwrap_or(443);
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| invalid("无法解析 base_url 主机名"))?;
        for a in addrs {
            check_ip(a.ip())?;
        }
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let root = base.as_str().trim_end_matches('/').to_string();
    let mut ids = Vec::new();
    let mut after: Option<String> = None;
    for _page in 0..20 {
        let mut url = format!("{root}/models");
        if format == ApiFormat::Messages {
            url.push_str("?limit=1000");
            if let Some(a) = &after {
                url.push_str("&after_id=");
                url.push_str(&urlencode(a));
            }
        }
        let mut req = client.get(&url);
        if let Some(k) = key {
            req = match (format, auth) {
                (ApiFormat::Messages, AuthStyle::ApiKey) => req.header("x-api-key", k),
                _ => req.bearer_auth(k),
            };
        }
        if format == ApiFormat::Messages {
            req = req.header("anthropic-version", "2023-06-01");
        }
        let mut resp = req
            .send()
            .await
            .map_err(|e| invalid(format!("请求模型列表失败：{}", e.without_url())))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(invalid(format!(
                "模型列表接口返回 HTTP {}",
                status.as_u16()
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| invalid(format!("读取模型列表失败：{}", e.without_url())))?
        {
            body.extend_from_slice(&chunk);
            if body.len() > MODELS_BODY_CAP {
                return Err(invalid("模型列表响应过大"));
            }
        }
        let v: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| invalid("模型列表不是 JSON"))?;
        let data = v["data"]
            .as_array()
            .or_else(|| v["models"].as_array())
            .ok_or_else(|| invalid("模型列表格式无法识别（缺少 data 数组）"))?;
        for m in data {
            if let Some(id) = m["id"].as_str().or_else(|| m["name"].as_str()) {
                ids.push(id.to_string());
            }
        }
        if v["has_more"].as_bool() == Some(true)
            && let Some(last) = v["last_id"].as_str()
        {
            after = Some(last.to_string());
            continue;
        }
        break;
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> (Settings, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.storage.data_dir = dir.path().to_path_buf();
        let s = Settings::new(Arc::new(cfg));
        s.set_file_key_allowed(true);
        (s, dir)
    }

    #[test]
    fn key_roundtrip_with_file_key() {
        let (s, dir) = settings();
        let c = s.encrypt_key("sk-test").unwrap();
        assert!(!c.contains("sk-test"));
        assert_eq!(s.decrypt_key(&c).unwrap(), "sk-test");
        let key = dir.path().join("secret.key");
        assert!(key.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn key_storage_refused_without_isolation() {
        let (s, _dir) = settings();
        s.set_file_key_allowed(false);
        if secret(SECRET_KEY_ENV).is_none() {
            assert_eq!(s.key_storage(), "unavailable");
            assert!(s.encrypt_key("x").is_err());
        }
    }

    #[test]
    fn base_url_rules() {
        assert!(validate_base_url("https://api.example.com/v1").is_ok());
        assert!(validate_base_url("http://127.0.0.1:8080/v1").is_ok());
        assert!(validate_base_url("http://10.0.0.2/v1").is_ok());
        assert!(validate_base_url("http://169.254.169.254/latest").is_err());
        assert!(validate_base_url("ftp://x").is_err());
        assert!(validate_base_url("https://u:p@x.com").is_err());
    }

    #[tokio::test]
    async fn provider_crud_and_routing() {
        let (s, _dir) = settings();
        let db = crate::store::open_memory().await;
        let id = create_provider(
            &s,
            &db,
            ProviderInput {
                name: Some("relay".into()),
                api_format: Some(ApiFormat::Messages),
                base_url: Some("https://relay.example.com/v1/".into()),
                auth: None,
                default_model: Some("m1".into()),
                api_key: Some("sk-abc".into()),
            },
        )
        .await
        .unwrap();
        let p = s
            .snapshot()
            .providers
            .iter()
            .find(|p| p.id == id)
            .cloned()
            .unwrap();
        assert!(p.has_key);
        assert_eq!(p.base_url, "https://relay.example.com/v1");

        // base_url change without a new key is refused
        let err = update_provider(
            &s,
            &db,
            &id,
            ProviderInput {
                name: None,
                api_format: None,
                base_url: Some("https://evil.example.com".into()),
                auth: None,
                default_model: None,
                api_key: None,
            },
        )
        .await
        .unwrap_err();
        assert!(err.downcast_ref::<Invalid>().is_some());

        assert!(s.resolve("daily").is_none());
        replace_routes(
            &s,
            &db,
            &[Route {
                kind: "default".into(),
                provider: id.clone(),
                model: String::new(),
                effort: "high".into(),
            }],
        )
        .await
        .unwrap();
        let r = s.resolve("daily").unwrap();
        assert_eq!(r.model, "m1");
        assert_eq!(r.effort, "high");
        assert!(r.has_key);
        assert_eq!(r.key_env, provider_key_env(&id));
        let env = s.provider_env(&db).await;
        assert_eq!(env, vec![(provider_key_env(&id), "sk-abc".to_string())]);

        assert!(delete_provider(&s, &db, &id).await.unwrap());
        assert!(s.resolve("daily").is_none());
    }

    #[tokio::test]
    async fn lists_models_for_both_formats() {
        use axum::extract::Query;
        use axum::http::HeaderMap;
        use axum::routing::get;
        async fn openai(h: HeaderMap) -> axum::Json<serde_json::Value> {
            assert_eq!(h["authorization"], "Bearer k1");
            axum::Json(serde_json::json!({ "data": [{ "id": "gpt-b" }, { "id": "gpt-a" }] }))
        }
        async fn anthropic(
            h: HeaderMap,
            Query(q): Query<BTreeMap<String, String>>,
        ) -> axum::Json<serde_json::Value> {
            assert_eq!(h["x-api-key"], "k2");
            assert!(h.contains_key("anthropic-version"));
            if q.get("after_id").map(String::as_str) == Some("c1") {
                axum::Json(serde_json::json!({ "data": [{ "id": "c2" }], "has_more": false }))
            } else {
                axum::Json(
                    serde_json::json!({ "data": [{ "id": "c1" }], "has_more": true, "last_id": "c1" }),
                )
            }
        }
        let app = axum::Router::new()
            .route("/o/models", get(openai))
            .route("/a/models", get(anthropic));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

        let o = fetch_models(
            ApiFormat::Responses,
            &format!("http://{addr}/o/"),
            AuthStyle::ApiKey,
            Some("k1"),
        )
        .await
        .unwrap();
        assert_eq!(o, vec!["gpt-a", "gpt-b"]);
        let a = fetch_models(
            ApiFormat::Messages,
            &format!("http://{addr}/a"),
            AuthStyle::ApiKey,
            Some("k2"),
        )
        .await
        .unwrap();
        assert_eq!(a, vec!["c1", "c2"]);
        let err = fetch_models(
            ApiFormat::Responses,
            &format!("http://{addr}/missing"),
            AuthStyle::ApiKey,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("404"));
    }
}
