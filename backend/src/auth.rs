//! Dashboard accounts, browser sessions and API tokens.
//!
//! * The first administrator is created by the setup wizard, which needs a one-time setup code
//!   written to `<data_dir>/setup-code` (0600) and to the log while no account exists.
//! * Browsers authenticate with an HttpOnly, SameSite=Strict session cookie; sessions slide
//!   (`[auth] session_days`) and expire after `idle_hours` without use.
//! * Server changes from the dashboard additionally need a recent password confirmation
//!   ("sudo", 10 minutes).
//! * Machines (MCP clients, scripts) use API tokens with a `read` or `ops` scope. The old
//!   `TSM_API_TOKEN` / `TSM_OPS_TOKEN` environment tokens still work but are deprecated.
//!
//! Passwords are argon2id PHC strings; session and API tokens are stored as sha256 only.

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde::{Deserialize, Serialize};

use crate::helper::fsutil::sha256_hex;
use crate::model::now_ms;
use crate::settings::Invalid;
use crate::state::Shared;
use crate::store::Db;

pub const COOKIE: &str = "tsm_session";
pub const SUDO_MS: i64 = 10 * 60_000;
pub const TOKEN_PREFIX: &str = "tsm_";
const MIN_PASSWORD: usize = 10;
const MAX_FAILURES: u32 = 5;
const LOCK_MS: i64 = 15 * 60_000;
/// Session `last_seen` is written at most this often.
const TOUCH_MS: i64 = 60_000;

fn invalid(msg: impl Into<String>) -> anyhow::Error {
    Invalid(msg.into()).into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random(bytes: usize) -> Result<String> {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).map_err(|e| anyhow!("rng: {e}"))?;
    Ok(B64URL.encode(b))
}

// ---------------------------------------------------------------- principal

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Read,
    Ops,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Scope::Read),
            "ops" => Some(Scope::Ops),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Ops => "ops",
        }
    }
}

/// Who is calling. Inserted into request extensions by `api::identify`.
#[derive(Debug, Clone)]
pub enum Principal {
    /// A signed-in account (browser session).
    User {
        id: i64,
        username: String,
        session: String,
        sudo_until: i64,
    },
    /// An API token from the dashboard.
    Token { id: i64, name: String, scope: Scope },
    /// The deprecated environment tokens. `admin` = TSM_API_TOKEN (settings writes),
    /// `ops` = TSM_OPS_TOKEN (server changes).
    Legacy { admin: bool, ops: bool },
}

impl Principal {
    pub fn is_user(&self) -> bool {
        matches!(self, Principal::User { .. })
    }

    /// May change TServerMonitor's own settings.
    pub fn can_admin(&self) -> bool {
        match self {
            Principal::User { .. } => true,
            Principal::Legacy { admin, .. } => *admin,
            Principal::Token { .. } => false,
        }
    }

    /// May change the server through the ops helper right now.
    pub fn can_ops(&self, now: i64) -> bool {
        match self {
            Principal::User { sudo_until, .. } => *sudo_until > now,
            Principal::Token { scope, .. } => *scope == Scope::Ops,
            Principal::Legacy { ops, .. } => *ops,
        }
    }

    /// Recorded in the audit log.
    pub fn actor(&self) -> String {
        match self {
            Principal::User { username, .. } => username.clone(),
            Principal::Token { name, .. } => format!("token:{name}"),
            Principal::Legacy { .. } => "legacy-token".into(),
        }
    }
}

// ---------------------------------------------------------------- runtime

#[derive(Default)]
pub struct Runtime {
    setup_code: Mutex<Option<String>>,
    /// limiter key -> (consecutive failures, locked until)
    failures: Mutex<HashMap<String, (u32, i64)>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Runtime {
    fn check_locked(&self, key: &str, now: i64) -> Result<()> {
        if let Some((_, until)) = lock(&self.failures).get(key)
            && *until > now
        {
            let mins = (*until - now + 59_999) / 60_000;
            return Err(invalid(format!("失败次数过多，请 {mins} 分钟后再试")));
        }
        Ok(())
    }

    fn record(&self, key: &str, ok: bool, now: i64) {
        let mut m = lock(&self.failures);
        if ok {
            m.remove(key);
            return;
        }
        let e = m.entry(key.to_string()).or_insert((0, 0));
        e.0 += 1;
        if e.0 >= MAX_FAILURES {
            *e = (0, now + LOCK_MS);
        }
        // keep the map bounded
        if m.len() > 10_000 {
            m.retain(|_, (n, until)| *until > now || *n > 0);
        }
    }
}

// ---------------------------------------------------------------- passwords

pub async fn hash_password(password: &str) -> Result<String> {
    let pw = password.to_string();
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(pw.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| anyhow!("hashing password: {e}"))
    })
    .await?
}

pub async fn verify_password(hash: &str, password: &str) -> bool {
    let (h, pw) = (hash.to_string(), password.to_string());
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&h).ok().is_some_and(|parsed| {
            Argon2::default()
                .verify_password(pw.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await
    .unwrap_or(false)
}

pub fn check_username(name: &str) -> Result<String> {
    let n = name.trim();
    let ok = (3..=32).contains(&n.len())
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    if !ok {
        return Err(invalid("用户名需为 3–32 位字母、数字、下划线、点或连字符"));
    }
    Ok(n.to_string())
}

pub fn check_password(pw: &str) -> Result<()> {
    if pw.chars().count() < MIN_PASSWORD {
        return Err(invalid(format!("密码至少 {MIN_PASSWORD} 位")));
    }
    if pw.len() > 256 {
        return Err(invalid("密码过长"));
    }
    Ok(())
}

// ---------------------------------------------------------------- users

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

pub async fn user_count(db: &Db) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(db)
        .await?)
}

pub async fn list_users(db: &Db) -> Result<Vec<User>> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT id, username, created_at, last_login_at FROM users ORDER BY id",
    )
    .fetch_all(db)
    .await?)
}

pub async fn create_user(db: &Db, username: &str, password: &str) -> Result<i64> {
    let username = check_username(username)?;
    check_password(password)?;
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(db)
        .await?;
    if exists.is_some() {
        return Err(invalid("用户名已存在"));
    }
    let hash = hash_password(password).await?;
    let now = now_ms();
    Ok(sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, created_at, password_changed_at) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(&username)
    .bind(hash)
    .bind(now)
    .bind(now)
    .fetch_one(db)
    .await?)
}

pub async fn delete_user(db: &Db, id: i64, me: i64) -> Result<()> {
    if id == me {
        return Err(invalid("不能删除当前登录的账号"));
    }
    if user_count(db).await? <= 1 {
        return Err(invalid("至少保留一个管理员"));
    }
    let n = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(invalid("账号不存在"));
    }
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// Sets a new password and signs out every session of the user except `keep`.
pub async fn set_password(db: &Db, user_id: i64, password: &str, keep: Option<&str>) -> Result<()> {
    check_password(password)?;
    let hash = hash_password(password).await?;
    sqlx::query("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?")
        .bind(hash)
        .bind(now_ms())
        .bind(user_id)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = ? AND id != ?")
        .bind(user_id)
        .bind(keep.unwrap_or(""))
        .execute(db)
        .await?;
    Ok(())
}

async fn password_hash_of(db: &Db, user_id: i64) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(db)
            .await?,
    )
}

/// A valid argon2id hash of a random password, verified against when the user does not exist
/// so that a wrong user name takes as long as a wrong password.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$6sJQ3PJwM5mI3Qp1uUM2PJcXJm6+2y4b1d0NQ2l7r1Y";

// ---------------------------------------------------------------- setup

/// Called at startup: while no account exists, creates the setup code and returns it.
pub async fn init(state: &Shared) -> Result<Option<String>> {
    if user_count(&state.db).await? > 0 {
        *lock(&state.auth.setup_code) = None;
        let _ = std::fs::remove_file(setup_code_path(state));
        return Ok(None);
    }
    let code: String = random(9)?
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(10)
        .collect::<String>()
        .to_ascii_uppercase();
    let path = setup_code_path(state);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::remove_file(&path);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        writeln!(f, "{code}")?;
    }
    *lock(&state.auth.setup_code) = Some(code.clone());
    Ok(Some(code))
}

pub fn setup_code_path(state: &Shared) -> std::path::PathBuf {
    state.cfg.storage.data_dir.join("setup-code")
}

pub fn setup_required(state: &Shared) -> bool {
    lock(&state.auth.setup_code).is_some()
}

/// Creates the first administrator. Fails once any account exists.
pub async fn setup(
    state: &Shared,
    code: &str,
    username: &str,
    password: &str,
    remote: &str,
) -> Result<i64> {
    let now = now_ms();
    let key = format!("setup|{remote}");
    state.auth.check_locked(&key, now)?;
    let expected = lock(&state.auth.setup_code).clone();
    let Some(expected) = expected else {
        return Err(invalid("已经完成初始化"));
    };
    let given = code.trim().to_ascii_uppercase();
    if !ct_eq(given.as_bytes(), expected.as_bytes()) {
        state.auth.record(&key, false, now);
        return Err(invalid(
            "setup 码不正确（见服务器上的 setup-code 文件或启动日志）",
        ));
    }
    if user_count(&state.db).await? > 0 {
        return Err(invalid("已经完成初始化"));
    }
    let id = create_user(&state.db, username, password).await?;
    state.auth.record(&key, true, now);
    *lock(&state.auth.setup_code) = None;
    let _ = std::fs::remove_file(setup_code_path(state));
    tracing::info!("administrator account created by the setup wizard");
    Ok(id)
}

// ---------------------------------------------------------------- login and sessions

pub async fn login(state: &Shared, username: &str, password: &str, remote: &str) -> Result<User> {
    let now = now_ms();
    let key = format!("login|{remote}|{}", username.trim().to_ascii_lowercase());
    state.auth.check_locked(&key, now)?;
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE username = ?")
            .bind(username.trim())
            .fetch_optional(&state.db)
            .await?;
    let ok = match &row {
        Some((_, hash)) => verify_password(hash, password).await,
        None => {
            let _ = verify_password(DUMMY_HASH, password).await;
            false
        }
    };
    state.auth.record(&key, ok, now);
    let Some((id, _)) = row.filter(|_| ok) else {
        tracing::warn!("failed login for {:?} from {remote}", username.trim());
        return Err(invalid("用户名或密码不正确"));
    };
    sqlx::query("UPDATE users SET last_login_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(sqlx::query_as::<_, User>(
        "SELECT id, username, created_at, last_login_at FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await?)
}

/// Creates a session and returns the cookie value (only ever sent to the browser).
pub async fn create_session(
    state: &Shared,
    user_id: i64,
    remote: &str,
    user_agent: &str,
) -> Result<String> {
    let token = random(32)?;
    let now = now_ms();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, created_at, last_seen, expires_at, remote, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(sha256_hex(token.as_bytes()))
    .bind(user_id)
    .bind(now)
    .bind(now)
    .bind(now + state.cfg.auth.session_days * 86_400_000)
    .bind(remote)
    .bind(user_agent.chars().take(200).collect::<String>())
    .execute(&state.db)
    .await?;
    Ok(token)
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: String,
    user_id: i64,
    username: String,
    last_seen: i64,
    expires_at: i64,
    sudo_until: i64,
}

async fn session_principal(state: &Shared, cookie: &str) -> Result<Option<Principal>> {
    let id = sha256_hex(cookie.as_bytes());
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT s.id, s.user_id, u.username, s.last_seen, s.expires_at, s.sudo_until
         FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?;
    let Some(s) = row else { return Ok(None) };
    let now = now_ms();
    let idle = state.cfg.auth.idle_hours * 3_600_000;
    if s.expires_at <= now || s.last_seen + idle <= now {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(&s.id)
            .execute(&state.db)
            .await?;
        return Ok(None);
    }
    if now - s.last_seen >= TOUCH_MS {
        // sliding expiry
        sqlx::query("UPDATE sessions SET last_seen = ?, expires_at = ? WHERE id = ?")
            .bind(now)
            .bind(now + state.cfg.auth.session_days * 86_400_000)
            .bind(&s.id)
            .execute(&state.db)
            .await?;
    }
    Ok(Some(Principal::User {
        id: s.user_id,
        username: s.username,
        session: s.id,
        sudo_until: s.sudo_until,
    }))
}

pub async fn delete_session(db: &Db, session_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(session_id)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SessionView {
    pub id: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub expires_at: i64,
    pub remote: Option<String>,
    pub user_agent: Option<String>,
    #[sqlx(skip)]
    pub current: bool,
}

pub async fn list_sessions(db: &Db, user_id: i64, current: &str) -> Result<Vec<SessionView>> {
    let mut v = sqlx::query_as::<_, SessionView>(
        "SELECT id, created_at, last_seen, expires_at, remote, user_agent FROM sessions WHERE user_id = ? ORDER BY last_seen DESC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    for s in &mut v {
        s.current = s.id == current;
    }
    Ok(v)
}

pub async fn revoke_session(db: &Db, user_id: i64, id: &str) -> Result<()> {
    let n = sqlx::query("DELETE FROM sessions WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user_id)
        .execute(db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(invalid("会话不存在"));
    }
    Ok(())
}

/// Confirms the password for the current session; server changes are allowed until the
/// returned time.
pub async fn sudo(
    state: &Shared,
    user_id: i64,
    session: &str,
    password: &str,
    remote: &str,
) -> Result<i64> {
    let now = now_ms();
    let key = format!("sudo|{user_id}");
    state.auth.check_locked(&key, now)?;
    let hash = password_hash_of(&state.db, user_id)
        .await?
        .ok_or_else(|| invalid("账号不存在"))?;
    let ok = verify_password(&hash, password).await;
    state.auth.record(&key, ok, now);
    if !ok {
        tracing::warn!("failed password confirmation for user {user_id} from {remote}");
        return Err(invalid("密码不正确"));
    }
    let until = now + SUDO_MS;
    sqlx::query("UPDATE sessions SET sudo_until = ? WHERE id = ?")
        .bind(until)
        .bind(session)
        .execute(&state.db)
        .await?;
    Ok(until)
}

pub async fn change_password(
    state: &Shared,
    user_id: i64,
    session: &str,
    current: &str,
    new: &str,
) -> Result<()> {
    let hash = password_hash_of(&state.db, user_id)
        .await?
        .ok_or_else(|| invalid("账号不存在"))?;
    if !verify_password(&hash, current).await {
        return Err(invalid("当前密码不正确"));
    }
    set_password(&state.db, user_id, new, Some(session)).await
}

// ---------------------------------------------------------------- API tokens

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ApiToken {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub scope: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub async fn list_tokens(db: &Db) -> Result<Vec<ApiToken>> {
    Ok(sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, prefix, scope, created_at, expires_at, last_used_at, revoked_at FROM api_tokens ORDER BY id DESC",
    )
    .fetch_all(db)
    .await?)
}

/// Returns the token (shown once) and its stored record.
pub async fn create_token(
    db: &Db,
    name: &str,
    scope: Scope,
    expires_days: Option<i64>,
    created_by: i64,
) -> Result<(String, ApiToken)> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(invalid("令牌名称需为 1–64 个字符"));
    }
    if let Some(d) = expires_days
        && !(1..=3650).contains(&d)
    {
        return Err(invalid("有效期需为 1–3650 天"));
    }
    let plain = format!("{TOKEN_PREFIX}{}", random(32)?);
    let now = now_ms();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO api_tokens (name, token_hash, prefix, scope, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(sha256_hex(plain.as_bytes()))
    .bind(plain.chars().take(10).collect::<String>())
    .bind(scope.as_str())
    .bind(created_by)
    .bind(now)
    .bind(expires_days.map(|d| now + d * 86_400_000))
    .fetch_one(db)
    .await?;
    let t = sqlx::query_as::<_, ApiToken>(
        "SELECT id, name, prefix, scope, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db)
    .await?;
    Ok((plain, t))
}

pub async fn revoke_token(db: &Db, id: i64) -> Result<()> {
    let n = sqlx::query("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
        .bind(now_ms())
        .bind(id)
        .execute(db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(invalid("令牌不存在或已吊销"));
    }
    Ok(())
}

/// (id, name, scope, expires_at, revoked_at, last_used_at)
type TokenRow = (i64, String, String, Option<i64>, Option<i64>, Option<i64>);

async fn token_principal(db: &Db, plain: &str) -> Result<Option<Principal>> {
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT id, name, scope, expires_at, revoked_at, last_used_at FROM api_tokens WHERE token_hash = ?",
    )
    .bind(sha256_hex(plain.as_bytes()))
    .fetch_optional(db)
    .await?;
    let Some((id, name, scope, expires, revoked, last_used)) = row else {
        return Ok(None);
    };
    let now = now_ms();
    if revoked.is_some() || expires.is_some_and(|e| e <= now) {
        return Ok(None);
    }
    if last_used.is_none_or(|t| now - t >= TOUCH_MS) {
        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
            .bind(now)
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(Scope::parse(&scope).map(|scope| Principal::Token { id, name, scope }))
}

// ---------------------------------------------------------------- request identification

pub fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// Resolves the caller from (in order) the session cookie, an `Authorization: Bearer` API
/// token, and the deprecated environment tokens (`Authorization` / `X-TSM-Ops-Token`).
pub async fn identify(state: &Shared, headers: &HeaderMap) -> Option<Principal> {
    if let Some(c) = cookie_value(headers, COOKIE)
        && !c.is_empty()
    {
        match session_principal(state, c).await {
            Ok(Some(p)) => return Some(p),
            Ok(None) => {}
            Err(e) => tracing::warn!("session lookup: {e:#}"),
        }
    }
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    if let Some(b) = bearer
        && b.starts_with(TOKEN_PREFIX)
    {
        match token_principal(&state.db, b).await {
            Ok(Some(p)) => return Some(p),
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!("token lookup: {e:#}");
                return None;
            }
        }
    }
    // deprecated environment tokens
    let env_api = crate::config::secret(&state.cfg.server.token_env);
    let env_ops = crate::config::secret(&state.cfg.server.ops_token_env);
    let admin =
        matches!((bearer, &env_api), (Some(b), Some(e)) if ct_eq(b.as_bytes(), e.as_bytes()));
    let ops_header = headers.get("x-tsm-ops-token").and_then(|v| v.to_str().ok());
    let ops = matches!((ops_header, &env_ops), (Some(h), Some(e)) if ct_eq(h.as_bytes(), e.as_bytes()))
        || matches!((bearer, &env_ops), (Some(b), Some(e)) if ct_eq(b.as_bytes(), e.as_bytes()));
    (admin || ops).then_some(Principal::Legacy { admin, ops })
}

/// `Set-Cookie` value for a new session (or a clearing cookie when `value` is empty).
pub fn session_cookie(state: &Shared, value: &str, secure: bool) -> String {
    let max_age = if value.is_empty() {
        0
    } else {
        state.cfg.auth.session_days * 86_400
    };
    format!(
        "{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

/// Whether the session cookie should carry `Secure`.
pub fn secure_request(state: &Shared, headers: &HeaderMap, peer_loopback: bool) -> bool {
    match state.cfg.auth.secure_cookie.as_str() {
        "always" => true,
        "never" => false,
        // only trust X-Forwarded-Proto from a proxy on this host
        _ => {
            peer_loopback
                && headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.eq_ignore_ascii_case("https"))
        }
    }
}

/// Logs the setup code prominently while no account exists.
pub fn announce_setup(state: &Shared, code: &str) {
    tracing::warn!(
        "No administrator yet. Open the dashboard and complete the setup wizard with setup code {code} (also in {})",
        setup_code_path(state).display()
    );
}

/// `tsmonitor reset-password`: new random password for `username`, all its sessions ended.
pub async fn reset_password(db: &Db, username: &str) -> Result<String> {
    let id: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(db)
        .await?;
    let Some(id) = id else {
        let names: Vec<String> = list_users(db)
            .await?
            .into_iter()
            .map(|u| u.username)
            .collect();
        anyhow::bail!(
            "no account named {username:?} (accounts: {})",
            if names.is_empty() {
                "none, use the setup wizard".into()
            } else {
                names.join(", ")
            }
        );
    };
    let pw = random(15)?;
    set_password(db, id, &pw, None).await?;
    Ok(pw)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn state() -> (Shared, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.storage.data_dir = dir.path().to_path_buf();
        cfg.server.token_env = "TSM_TEST_AUTH_UNSET".into();
        cfg.server.ops_token_env = "TSM_TEST_AUTH_UNSET2".into();
        let s = crate::state::AppState::new(
            std::sync::Arc::new(cfg),
            crate::store::open_memory().await,
        );
        (s, dir)
    }

    #[test]
    fn dummy_hash_parses() {
        assert!(PasswordHash::new(DUMMY_HASH).is_ok());
    }

    #[tokio::test]
    async fn setup_is_one_time_and_needs_the_code() {
        let (s, _d) = state().await;
        let code = init(&s).await.unwrap().unwrap();
        assert!(setup_required(&s));
        let file = std::fs::read_to_string(setup_code_path(&s)).unwrap();
        assert_eq!(file.trim(), code);
        assert!(
            setup(&s, "WRONG", "admin", "correct horse battery", "1.1.1.1")
                .await
                .is_err()
        );
        assert!(setup(&s, &code, "admin", "short", "1.1.1.1").await.is_err());
        setup(
            &s,
            &code.to_lowercase(),
            "admin",
            "correct horse battery",
            "1.1.1.1",
        )
        .await
        .unwrap();
        assert!(!setup_required(&s));
        assert!(!setup_code_path(&s).exists());
        assert!(
            setup(&s, &code, "evil", "correct horse battery", "2.2.2.2")
                .await
                .is_err()
        );
        // restart: no new code once an account exists
        assert!(init(&s).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn login_sessions_sudo_and_lockout() {
        let (s, _d) = state().await;
        let id = create_user(&s.db, "admin", "correct horse battery")
            .await
            .unwrap();
        assert!(
            login(&s, "admin", "wrong-password!", "9.9.9.9")
                .await
                .is_err()
        );
        let u = login(&s, "ADMIN", "correct horse battery", "9.9.9.9")
            .await
            .unwrap();
        assert_eq!(u.id, id);

        let cookie = create_session(&s, id, "9.9.9.9", "test").await.unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            format!("a=b; {COOKIE}={cookie}").parse().unwrap(),
        );
        let p = identify(&s, &h).await.unwrap();
        let Principal::User {
            session,
            sudo_until,
            ..
        } = p.clone()
        else {
            panic!()
        };
        assert!(!p.can_ops(now_ms()));
        assert_eq!(sudo_until, 0);
        assert!(sudo(&s, id, &session, "nope-nope-nope", "x").await.is_err());
        sudo(&s, id, &session, "correct horse battery", "x")
            .await
            .unwrap();
        assert!(identify(&s, &h).await.unwrap().can_ops(now_ms()));

        // password change keeps this session, ends the others
        let other = create_session(&s, id, "8.8.8.8", "other").await.unwrap();
        change_password(
            &s,
            id,
            &session,
            "correct horse battery",
            "another long password",
        )
        .await
        .unwrap();
        let mut h2 = HeaderMap::new();
        h2.insert(
            axum::http::header::COOKIE,
            format!("{COOKIE}={other}").parse().unwrap(),
        );
        assert!(identify(&s, &h2).await.is_none());
        assert!(identify(&s, &h).await.is_some());

        // lockout after repeated failures, also for the right password
        for _ in 0..MAX_FAILURES {
            let _ = login(&s, "admin", "bad-bad-bad-bad", "7.7.7.7").await;
        }
        let e = login(&s, "admin", "another long password", "7.7.7.7")
            .await
            .unwrap_err();
        assert!(format!("{e}").contains("分钟"), "{e}");
        // another address is not affected
        assert!(
            login(&s, "admin", "another long password", "6.6.6.6")
                .await
                .is_ok()
        );

        // the last account cannot be deleted
        assert!(delete_user(&s.db, id, 999).await.is_err());
        let reset = reset_password(&s.db, "admin").await.unwrap();
        assert!(identify(&s, &h).await.is_none());
        assert!(login(&s, "admin", &reset, "5.5.5.5").await.is_ok());
    }

    #[tokio::test]
    async fn api_tokens_and_legacy_env_tokens() {
        let (s, _d) = state().await;
        let (plain, t) = create_token(&s.db, "ci", Scope::Read, Some(30), 1)
            .await
            .unwrap();
        assert!(plain.starts_with(TOKEN_PREFIX));
        assert_eq!(t.prefix, &plain[..10]);
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {plain}").parse().unwrap(),
        );
        let p = identify(&s, &h).await.unwrap();
        assert!(!p.can_ops(now_ms()) && !p.can_admin());
        assert_eq!(p.actor(), "token:ci");
        revoke_token(&s.db, t.id).await.unwrap();
        assert!(identify(&s, &h).await.is_none());

        let (ops, _) = create_token(&s.db, "agent", Scope::Ops, None, 1)
            .await
            .unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {ops}").parse().unwrap(),
        );
        assert!(identify(&s, &h).await.unwrap().can_ops(now_ms()));
        // a stored hash is not a credential
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", sha256_hex(ops.as_bytes()))
                .parse()
                .unwrap(),
        );
        assert!(identify(&s, &h).await.is_none());

        // deprecated env tokens
        unsafe { std::env::set_var("TSM_TEST_AUTH_LEGACY_API", "legacy-api") };
        unsafe { std::env::set_var("TSM_TEST_AUTH_LEGACY_OPS", "legacy-ops-0123456789") };
        let mut cfg = (*s.cfg).clone();
        cfg.server.token_env = "TSM_TEST_AUTH_LEGACY_API".into();
        cfg.server.ops_token_env = "TSM_TEST_AUTH_LEGACY_OPS".into();
        let s2 = crate::state::AppState::new(std::sync::Arc::new(cfg), s.db.clone());
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer legacy-api".parse().unwrap(),
        );
        let p = identify(&s2, &h).await.unwrap();
        assert!(p.can_admin() && !p.can_ops(now_ms()));
        h.insert("x-tsm-ops-token", "legacy-ops-0123456789".parse().unwrap());
        assert!(identify(&s2, &h).await.unwrap().can_ops(now_ms()));
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer wrong".parse().unwrap(),
        );
        assert!(identify(&s2, &h).await.is_none());
    }
}
