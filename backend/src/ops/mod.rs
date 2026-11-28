//! Server management (nginx, firewall, SSH, Docker) through the optional root ops helper.
//!
//! The daemon itself never changes the host. Reads go to the helper when its domain is
//! enabled, with best-effort local fallbacks (the daemon can usually read `/etc/nginx` and
//! `sshd_config`, and Docker through its read-only proxy). Every write becomes an `ops_jobs`
//! row plus an `audit_log` row, runs in the helper, and streams its log as `ops_job` events.
//!
//! Shared modules (`proto`, `validate`, and the per-domain models) are used by both sides.

pub mod calls;
pub mod client;
pub mod docker;
pub mod firewall;
pub mod nginx;
pub mod nginx_site;
pub mod proto;
pub mod ssh;
pub mod validate;

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::model::{Event, now_ms};
use crate::state::Shared;
use proto::{Actor, ErrorCode, OpError, OpResult};

const MAX_LOG: usize = 256 * 1024;
const CAPS_TTL_MS: i64 = 30_000;

/// Who asked for a change.
#[derive(Debug, Clone, Serialize)]
pub struct Via {
    /// web | mcp | agent (built-in agent, approved request)
    pub via: &'static str,
    pub remote: Option<String>,
    /// account name, `token:<name>` or `legacy-token`
    pub actor: String,
}

#[derive(Default)]
pub struct Runtime {
    caps: Mutex<Option<(i64, Result<Value, String>)>>,
    isolation_ok: AtomicBool,
    waiters: Mutex<HashMap<i64, watch::Sender<bool>>>,
    last_pending: Mutex<Value>,
}

impl Runtime {
    pub fn set_isolation(&self, ok: bool) {
        self.isolation_ok.store(ok, Ordering::Relaxed);
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn secret(state: &Shared) -> Option<String> {
    crate::config::secret(&state.cfg.ops.secret_env)
}

// ---------------------------------------------------------------- capabilities

#[derive(Debug, Clone, Serialize)]
pub struct Capabilities {
    /// The helper answered.
    pub available: bool,
    pub reason: Option<String>,
    pub version: Option<String>,
    pub dry_run: bool,
    pub confirm_secs: u64,
    /// Changes can be submitted (helper + ops token + sandbox isolation).
    pub write_ready: bool,
    pub write_reason: Option<String>,
    pub domains: Value,
}

async fn hello(state: &Shared) -> Result<Value, String> {
    let Some(secret) = secret(state) else {
        return Err(format!(
            "未配置与运维助手共享的密钥（环境变量 {}）",
            state.cfg.ops.secret_env
        ));
    };
    let socket = &state.cfg.ops.helper_socket;
    if !crate::updater::helper_available(socket) {
        return Err(format!("运维助手未安装或未启动（{}）", socket.display()));
    }
    client::call_raw(
        socket,
        &secret,
        "hello",
        json!({}),
        false,
        Actor::default(),
        |_| {},
    )
    .await
    .map_err(|e| format!("运维助手不可用：{}", e.message))
}

async fn hello_cached(state: &Shared) -> Result<Value, String> {
    if let Some((at, v)) = lock(&state.ops.caps).as_ref()
        && now_ms() - at < CAPS_TTL_MS
    {
        return v.clone();
    }
    let v = hello(state).await;
    *lock(&state.ops.caps) = Some((now_ms(), v.clone()));
    v
}

pub fn invalidate_caps(state: &Shared) {
    *lock(&state.ops.caps) = None;
}

pub async fn capabilities(state: &Shared) -> Capabilities {
    let h = hello_cached(state).await;
    let isolated =
        state.ops.isolation_ok.load(Ordering::Relaxed) || state.cfg.ops.allow_without_sandbox;
    let (available, reason, hv) = match h {
        Ok(v) => (true, None, v),
        Err(e) => (false, Some(e), Value::Null),
    };
    let write_reason = if !available {
        reason.clone()
    } else if !isolated {
        Some("分析脚本沙箱没有内核级隔离，已禁止通过助手修改服务器（可在 [ops] allow_without_sandbox 中放开）".into())
    } else {
        None
    };
    Capabilities {
        available,
        reason,
        version: hv["version"].as_str().map(str::to_string),
        dry_run: hv["dry_run"].as_bool().unwrap_or(false),
        confirm_secs: hv["confirm_secs"].as_u64().unwrap_or(0),
        write_ready: write_reason.is_none(),
        write_reason,
        domains: if hv["domains"].is_object() {
            hv["domains"].clone()
        } else {
            json!({})
        },
    }
}

fn domain_enabled(caps: &Value, d: &str) -> bool {
    caps["domains"][d]["enabled"].as_bool().unwrap_or(false)
}

// ---------------------------------------------------------------- reads

/// Calls served by [`read`].
pub const READ_CALLS: &[&str] = &[
    "docker.containers",
    "docker.images",
    "docker.volumes",
    "docker.networks",
    "nginx.sites",
    "nginx.files",
    "nginx.file",
    "nginx.site_get",
    "nginx.status",
    "nginx.versions",
    "nginx.log_tail",
    "firewall.status",
    "ssh.config",
    "ssh.keys",
];

/// Read through the helper (no job, no audit).
pub async fn query(state: &Shared, call: &str, args: Value) -> OpResult<Value> {
    let secret =
        secret(state).ok_or_else(|| OpError::new(ErrorCode::Unsupported, "未配置运维助手密钥"))?;
    client::call_raw(
        &state.cfg.ops.helper_socket,
        &secret,
        call,
        args,
        false,
        Actor::default(),
        |_| {},
    )
    .await
}

/// A read with `source` = helper | local. Falls back to what the daemon can see itself.
pub async fn read(state: &Shared, call: &str, args: Value) -> OpResult<Value> {
    if !READ_CALLS.contains(&call) {
        return Err(OpError::invalid(format!("不支持的查询 {call}")));
    }
    let domain = call.split('.').next().unwrap_or_default();
    let caps = hello_cached(state).await.unwrap_or(Value::Null);
    if domain_enabled(&caps, domain) {
        let v = query(state, call, args).await?;
        return Ok(json!({ "source": "helper", "data": v }));
    }
    let local = local_read(state, call, &args).await?;
    Ok(json!({ "source": "local", "data": local }))
}

async fn local_read(state: &Shared, call: &str, args: &Value) -> OpResult<Value> {
    let root = &state.cfg.ops.nginx_root;
    let edit = crate::helper::config::NginxDomain::default().edit_dirs;
    let need_helper = |what: &str| {
        OpError::new(
            ErrorCode::Unsupported,
            format!("{what}需要启用运维助手中的对应功能（root 权限读取）"),
        )
    };
    match call {
        "nginx.sites" => {
            if !root.is_dir() {
                return Err(OpError::new(
                    ErrorCode::Unsupported,
                    format!("未找到 nginx 配置目录 {}", root.display()),
                ));
            }
            Ok(json!({ "layout": nginx::layout(root), "sites": nginx::sites(root) }))
        }
        "nginx.files" => Ok(json!(nginx::files(root, &edit))),
        "nginx.file" => {
            let path = args["path"].as_str().unwrap_or_default();
            let mut v = nginx::read_file(root, path, &edit)?;
            v.editable = false;
            Ok(json!(v))
        }
        "ssh.config" => {
            let main = std::fs::read_to_string(&state.cfg.ops.sshd_config).map_err(|e| {
                OpError::new(
                    ErrorCode::Unsupported,
                    format!("读取 {}：{e}", state.cfg.ops.sshd_config.display()),
                )
            })?;
            Ok(json!({
                "available": false,
                "effective": {},
                "ports": ssh::ports_from_config(&main),
                "managed": {},
                "includes_dropins": ssh::includes_dropins(&main),
                "options": ssh::OPTIONS.iter().map(|(k, v)| json!({ "key": k, "values": v })).collect::<Vec<_>>(),
            }))
        }
        "nginx.site_get" => Err(need_helper("查看站点设置")),
        "nginx.status" | "nginx.versions" => Err(need_helper("管理 nginx 服务与版本")),
        "nginx.log_tail" => Err(need_helper("查看 nginx 日志")),
        "ssh.keys" => Err(need_helper("查看各用户的 authorized_keys ")),
        "firewall.status" => Err(need_helper("查看防火墙规则")),
        c if c.starts_with("docker.") => {
            let d = crate::collect::docker::connect()
                .map_err(|e| OpError::new(ErrorCode::Unsupported, format!("Docker 不可用：{e}")))?;
            let r = match c {
                "docker.containers" => docker::containers(&d, &[]).await.map(|list| {
                    let p = docker::projects(&list, &HashMap::new());
                    json!({ "projects": p, "containers": list })
                }),
                "docker.images" => docker::images(&d).await.map(|v| json!(v)),
                "docker.volumes" => docker::volumes(&d).await.map(|v| json!(v)),
                "docker.networks" => docker::networks(&d).await.map(|v| json!(v)),
                _ => return Err(OpError::invalid(format!("unknown read {c}"))),
            };
            r.map_err(|e| {
                OpError::new(
                    ErrorCode::Unsupported,
                    format!("通过只读代理读取失败（代理可能未开放 IMAGES/VOLUMES/NETWORKS）：{e}"),
                )
            })
        }
        _ => Err(OpError::invalid(format!("unknown read {call}"))),
    }
}

/// Active login sessions (`who`); works without the helper.
pub async fn sessions() -> Vec<ssh::Session> {
    match tokio::process::Command::new("who")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .await
    {
        Ok(o) if o.status.success() => ssh::parse_who(&String::from_utf8_lossy(&o.stdout)),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------- jobs

#[derive(Debug, Clone, Serialize)]
pub struct Job {
    pub id: i64,
    pub domain: String,
    pub call: String,
    pub summary: String,
    pub args: Value,
    pub dry_run: bool,
    pub via: String,
    pub remote: Option<String>,
    pub actor: Option<String>,
    pub status: String,
    pub error: Option<String>,
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct JobRow {
    id: i64,
    domain: String,
    call: String,
    summary: String,
    args: String,
    dry_run: bool,
    via: String,
    remote: Option<String>,
    actor: Option<String>,
    status: String,
    error: Option<String>,
    result: Option<String>,
    log: Option<String>,
    started_at: i64,
    finished_at: Option<i64>,
}

impl From<JobRow> for Job {
    fn from(r: JobRow) -> Self {
        Job {
            id: r.id,
            domain: r.domain,
            call: r.call,
            summary: r.summary,
            args: serde_json::from_str(&r.args).unwrap_or(Value::Null),
            dry_run: r.dry_run,
            via: r.via,
            remote: r.remote,
            actor: r.actor,
            status: r.status,
            error: r.error,
            result: r.result.and_then(|s| serde_json::from_str(&s).ok()),
            log: r.log,
            started_at: r.started_at,
            finished_at: r.finished_at,
        }
    }
}

pub async fn close_stale_jobs(db: &crate::store::Db) -> Result<()> {
    sqlx::query("UPDATE ops_jobs SET status = 'unknown', finished_at = ? WHERE status = 'running'")
        .bind(now_ms())
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_jobs(
    db: &crate::store::Db,
    domain: Option<&str>,
    limit: i64,
) -> Result<Vec<Job>> {
    Ok(sqlx::query_as::<_, JobRow>(
        "SELECT id, domain, call, summary, args, dry_run, via, remote, actor, status, error, result, NULL AS log, started_at, finished_at
         FROM ops_jobs WHERE (?1 IS NULL OR domain = ?1) ORDER BY id DESC LIMIT ?2",
    )
        .bind(domain)
        .bind(limit.clamp(1, 200))
        .fetch_all(db)
        .await?
        .into_iter()
        .map(Into::into)
        .collect())
}

pub async fn get_job(db: &crate::store::Db, id: i64) -> Result<Option<Job>> {
    Ok(sqlx::query_as::<_, JobRow>(
        "SELECT id, domain, call, summary, args, dry_run, via, remote, actor, status, error, result, log, started_at, finished_at
         FROM ops_jobs WHERE id = ?",
    )
        .bind(id)
        .fetch_optional(db)
        .await?
        .map(Into::into))
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: i64,
    pub via: String,
    pub remote: Option<String>,
    pub actor: Option<String>,
    pub call: String,
    pub summary: String,
    pub dry_run: bool,
    pub outcome: String,
    pub detail: Option<String>,
    pub job_id: Option<i64>,
}

pub async fn list_audit(db: &crate::store::Db, limit: i64) -> Result<Vec<AuditEntry>> {
    Ok(sqlx::query_as::<_, AuditEntry>(
        "SELECT id, ts, via, remote, actor, call, summary, dry_run, outcome, detail, job_id FROM audit_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(db)
    .await?)
}

/// Replaces bulky or sensitive arguments before they are stored.
pub fn redact_args(args: &Value) -> Value {
    let mut v = args.clone();
    if let Some(o) = v.as_object_mut() {
        if let Some(c) = o.get("content").and_then(Value::as_str) {
            let summary = json!({
                "bytes": c.len(),
                "sha256": crate::helper::fsutil::sha256_hex(c.as_bytes()),
            });
            o.insert("content".into(), summary);
        }
        // certificate uploads: keep a fingerprint of the chain, nothing of the key
        if let Some(c) = o.get("cert_pem").and_then(Value::as_str) {
            let summary = json!({
                "bytes": c.len(),
                "sha256": crate::helper::fsutil::sha256_hex(c.as_bytes()),
            });
            o.insert("cert_pem".into(), summary);
        }
        if o.contains_key("key_pem") {
            o.insert("key_pem".into(), json!("<redacted>"));
        }
        if let Some(k) = o.get("key").and_then(Value::as_str) {
            let fp = ssh::check_new_key(k)
                .map(|(_, fp)| fp)
                .unwrap_or_else(|_| "invalid".into());
            o.insert("key".into(), json!({ "fingerprint": fp }));
        }
    }
    v
}

pub struct Submit {
    pub call: String,
    pub args: Value,
    pub dry_run: bool,
    pub summary: String,
    pub via: Via,
}

async fn audit(
    state: &Shared,
    s: &Submit,
    outcome: &str,
    detail: Option<&str>,
    job: Option<i64>,
) -> Option<i64> {
    sqlx::query_scalar(
        "INSERT INTO audit_log (ts, via, remote, actor, call, summary, dry_run, outcome, detail, job_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(now_ms())
    .bind(s.via.via)
    .bind(&s.via.remote)
    .bind(&s.via.actor)
    .bind(&s.call)
    .bind(&s.summary)
    .bind(s.dry_run)
    .bind(outcome)
    .bind(detail)
    .bind(job)
    .fetch_one(&state.db)
    .await
    .inspect_err(|e| tracing::warn!("audit log: {e:#}"))
    .ok()
}

/// Starts a change in the helper and returns the job id at once. The job keeps running if
/// the HTTP or MCP client goes away.
pub async fn submit(state: &Shared, s: Submit) -> Result<i64> {
    if let Err(e) = calls::check(&s.call, s.via.via != "web") {
        audit(state, &s, "refused", Some(&e.message), None).await;
        return Err(e.into());
    }
    let caps = capabilities(state).await;
    if let Some(why) = &caps.write_reason {
        audit(state, &s, "refused", Some(why), None).await;
        return Err(OpError::not_allowed(why.clone()).into());
    }
    let domain = s.call.split('.').next().unwrap_or_default().to_string();
    if domain != "pending" && !domain_enabled(&json!({ "domains": caps.domains }), &domain) {
        let why = format!("运维助手未启用 {domain} 管理");
        audit(state, &s, "refused", Some(&why), None).await;
        return Err(OpError::not_allowed(why).into());
    }
    let secret = secret(state).ok_or_else(|| OpError::not_allowed("未配置运维助手密钥"))?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO ops_jobs (domain, call, summary, args, dry_run, via, remote, actor, status, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?) RETURNING id",
    )
    .bind(&domain)
    .bind(&s.call)
    .bind(&s.summary)
    .bind(redact_args(&s.args).to_string())
    .bind(s.dry_run)
    .bind(s.via.via)
    .bind(&s.via.remote)
    .bind(&s.via.actor)
    .bind(now_ms())
    .fetch_one(&state.db)
    .await?;
    let audit_id = audit(state, &s, "started", None, Some(id)).await;
    let (tx, _) = watch::channel(false);
    lock(&state.ops.waiters).insert(id, tx);
    state.emit(Event::OpsJob {
        id,
        status: "running".into(),
        line: None,
    });

    let state = state.clone();
    tokio::spawn(async move {
        let mut log = String::new();
        let actor = Actor {
            via: s.via.via.into(),
            remote: s.via.remote.clone(),
            job: Some(id),
        };
        let res = client::call_raw(
            &state.cfg.ops.helper_socket,
            &secret,
            &s.call,
            s.args.clone(),
            s.dry_run,
            actor,
            |line| {
                if log.len() < MAX_LOG {
                    log.push_str(&line);
                    log.push('\n');
                }
                state.emit(Event::OpsJob {
                    id,
                    status: "running".into(),
                    line: Some(line),
                });
            },
        )
        .await;
        let (status, error, result) = match &res {
            Ok(v) => ("succeeded", None, Some(v.to_string())),
            Err(e) => ("failed", Some(e.message.clone()), None),
        };
        if let Err(e) = sqlx::query(
            "UPDATE ops_jobs SET status = ?, error = ?, result = ?, log = ?, finished_at = ? WHERE id = ?",
        )
        .bind(status)
        .bind(&error)
        .bind(&result)
        .bind(&log)
        .bind(now_ms())
        .bind(id)
        .execute(&state.db)
        .await
        {
            tracing::warn!("storing ops job {id}: {e:#}");
        }
        if let Some(aid) = audit_id {
            let _ = sqlx::query("UPDATE audit_log SET outcome = ?, detail = ? WHERE id = ?")
                .bind(status)
                .bind(&error)
                .bind(aid)
                .execute(&state.db)
                .await;
        }
        state.emit(Event::OpsJob {
            id,
            status: status.into(),
            line: None,
        });
        if let Some(tx) = lock(&state.ops.waiters).remove(&id) {
            let _ = tx.send(true);
        }
        if matches!(domain.as_str(), "firewall" | "ssh" | "pending") {
            refresh_pending(&state).await;
        }
    });
    Ok(id)
}

/// Waits up to `timeout` for a job to finish and returns it (finished or still running).
pub async fn wait(state: &Shared, id: i64, timeout: Duration) -> Result<Option<Job>> {
    let rx = lock(&state.ops.waiters).get(&id).map(|tx| tx.subscribe());
    if let Some(mut rx) = rx {
        let _ = tokio::time::timeout(timeout, rx.wait_for(|done| *done)).await;
    }
    get_job(&state.db, id).await
}

// ---------------------------------------------------------------- pending changes

pub async fn pending(state: &Shared) -> Value {
    let caps = hello_cached(state).await;
    if caps.is_err() {
        return json!([]);
    }
    query(state, "pending.list", json!({}))
        .await
        .unwrap_or_else(|_| json!([]))
}

async fn refresh_pending(state: &Shared) {
    let now = pending(state).await;
    let changed = {
        let mut last = lock(&state.ops.last_pending);
        let changed = *last != now;
        *last = now.clone();
        changed
    };
    if changed {
        state.emit(Event::OpsPending(now));
    }
}

/// Startup work: close jobs left running, keep the pending banner in sync with the helper
/// (it reverts on its own timer, so the daemon polls while something is pending).
pub fn spawn(state: &Shared) {
    let state = state.clone();
    tokio::spawn(async move {
        let mut tick = 0u64;
        loop {
            let busy = lock(&state.ops.last_pending)
                .as_array()
                .is_some_and(|a| !a.is_empty());
            if busy || tick.is_multiple_of(12) {
                refresh_pending(&state).await;
            }
            tick += 1;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Makes the daemon unreadable for other processes of the same uid (`/proc/<pid>/environ`,
/// ptrace), so an analysis script cannot lift the helper secret from the environment.
pub fn protect_secret() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with PR_SET_DUMPABLE only changes this process's dumpable flag.
        let r = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if r != 0 {
            tracing::warn!(
                "prctl(PR_SET_DUMPABLE): {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

// ---------------------------------------------------------------- redaction for agents

const PLACEHOLDER: &str = "<redacted>";
const SECRET_WORDS: &[&str] = &[
    "authorization",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "x-api-key",
    "private_key",
    "credential",
];

/// Config text for external agents: known token formats plus the value of any directive that
/// mentions a secret-like word are replaced with `<redacted>`.
pub fn redact_config(text: &str) -> String {
    text.lines()
        .map(|l| {
            let low = l.to_ascii_lowercase();
            let code = low.split('#').next().unwrap_or("");
            if SECRET_WORDS.iter().any(|w| code.contains(w)) {
                let indent = &l[..l.len() - l.trim_start().len()];
                let mut words = l.trim_start().splitn(2, char::is_whitespace);
                let directive = words.next().unwrap_or("");
                let semi = if l.trim_end().ends_with(';') { ";" } else { "" };
                format!("{indent}{directive} {PLACEHOLDER}{semi}")
            } else {
                crate::preprocess::redact_long(l)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// True when text still contains a redaction placeholder (an agent copied redacted output).
pub fn has_placeholder(text: &str) -> bool {
    [
        PLACEHOLDER,
        "<api-key>",
        "<aws-key>",
        "<email>",
        "<github-token>",
        "<jwt>",
        "<private-key>",
        "<slack-token>",
        "<telegram-token>",
        "<card?>",
    ]
    .iter()
    .any(|p| text.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_redaction_for_agents() {
        let t =
            "server {\n  proxy_set_header Authorization \"Basic dXNlcjpwYXNz\";\n  listen 80;\n}";
        let r = redact_config(t);
        assert!(!r.contains("dXNlcjpwYXNz"));
        assert!(r.contains("  proxy_set_header <redacted>;"));
        assert!(r.contains("listen 80;"));
        assert!(has_placeholder(&r));
        assert!(!has_placeholder(t));
    }

    #[test]
    fn args_are_redacted_before_storage() {
        let v = redact_args(&json!({ "path": "conf.d/a.conf", "content": "secret stuff" }));
        assert_eq!(v["content"]["bytes"], 12);
        assert!(v.to_string().find("secret stuff").is_none());
        let v = redact_args(
            &json!({ "name": "a", "cert_pem": "CERT", "key_pem": "-----BEGIN PRIVATE KEY-----x" }),
        );
        assert!(!v.to_string().contains("PRIVATE") && !v.to_string().contains("CERT\""));
        assert_eq!(v["cert_pem"]["bytes"], 4);
    }
}
