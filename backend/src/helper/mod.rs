//! Optional root ops helper (`tsmonitor helper`). The monitoring daemon stays unprivileged and
//! read-only; every change to nginx, the firewall, sshd or Docker is executed here, after this
//! process has checked it again against its own root-owned config.
//!
//! * Peers must run as root or an `allowed_uids` user **and** present the shared secret (the
//!   daemon's analysis scripts run as the same uid but get a cleared environment).
//! * Each domain is off by default; inside a domain only the operations in `allow` may write.
//! * Commands are argv arrays, never a shell. Files are backed up before every write and
//!   restored when validation (`nginx -t`, `sshd -t`) or the post-change probe fails.
//! * Firewall and sshd changes are reverted unless confirmed in time (see [`pending`]).
//! * One mutation per domain at a time; queries do not wait for mutations.
//!
//! Protocol: see [`crate::ops::proto`].

pub mod acme;
pub mod config;
pub mod docker;
pub mod exec;
pub mod firewall;
pub mod fsutil;
pub mod nginx;
pub mod nginx_cert;
pub mod nginx_docker;
pub mod nginx_pkg;
pub mod nginx_runtime;
pub mod nginx_site;
pub mod pending;
pub mod ssh;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, OwnedMutexGuard, mpsc};

use crate::ops::proto::{Actor, ErrorCode, MAX_LINE, OpError, OpResult, Reply, Request, VERSION};
pub use config::HelperConfig;

/// Job log: lines go to the client (and the journal) while it listens.
#[derive(Clone)]
pub struct Log {
    tx: mpsc::UnboundedSender<Reply>,
    call: Arc<str>,
}

impl Log {
    pub fn line(&self, line: impl Into<String>) {
        let line = line.into();
        tracing::info!(target: "helper", "[{}] {line}", self.call);
        let _ = self.tx.send(Reply::Log { line });
    }

    /// A log that only goes to the journal (tests, recovery).
    pub fn sink(call: &str) -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();
        Self {
            tx,
            call: call.into(),
        }
    }
}

pub struct Ctx {
    pub cfg: Arc<HelperConfig>,
    pub pending: Arc<pending::Pending>,
    locks: [Arc<Mutex<()>>; 4],
    /// nginx version, detected on first use and forgotten after an install or upgrade.
    pub nginx_version: std::sync::Mutex<Option<Option<(u32, u32, u32)>>>,
    pub acme: Arc<dyn acme::Issuer>,
    /// Sites with a certificate order in flight (orders run without the nginx lock).
    pub issuing: std::sync::Mutex<std::collections::HashSet<String>>,
}

pub struct Call<'a> {
    pub args: &'a Value,
    pub dry_run: bool,
    pub actor: &'a Actor,
    pub log: &'a Log,
}

impl Call<'_> {
    pub fn args<T: DeserializeOwned>(&self) -> OpResult<T> {
        let v = if self.args.is_null() {
            json!({})
        } else {
            self.args.clone()
        };
        serde_json::from_value(v).map_err(|e| OpError::invalid(format!("参数错误：{e}")))
    }
}

#[derive(Clone, Copy)]
pub enum Domain {
    Docker = 0,
    Nginx = 1,
    Firewall = 2,
    Ssh = 3,
}

impl Ctx {
    pub fn new(cfg: HelperConfig) -> Result<Arc<Self>> {
        let issuer = Arc::new(acme::AcmeClient::new(
            cfg.nginx.acme.clone(),
            &cfg.state_dir,
        ));
        Self::with_issuer(cfg, issuer)
    }

    pub fn with_issuer(cfg: HelperConfig, acme: Arc<dyn acme::Issuer>) -> Result<Arc<Self>> {
        let pending = pending::Pending::new(&cfg.state_dir, Duration::from_secs(cfg.confirm_secs))?;
        Ok(Arc::new(Self {
            cfg: Arc::new(cfg),
            pending,
            locks: std::array::from_fn(|_| Arc::new(Mutex::new(()))),
            nginx_version: std::sync::Mutex::new(None),
            acme,
            issuing: Default::default(),
        }))
    }

    /// Serialises mutations within a domain. Waits up to 30 s.
    pub async fn lock(&self, d: Domain) -> OpResult<OwnedMutexGuard<()>> {
        tokio::time::timeout(
            Duration::from_secs(30),
            self.locks[d as usize].clone().lock_owned(),
        )
        .await
        .map_err(|_| OpError::busy("同类操作正在进行，请稍后再试"))
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn not_enabled(domain: &str) -> OpError {
    OpError::not_allowed(format!(
        "助手未启用 {domain} 管理（/etc/tsmonitor/helper.toml 中 [{domain}] enabled = false）"
    ))
}

pub fn op_not_allowed(domain: &str, op: &impl serde::Serialize) -> OpError {
    let name = serde_json::to_value(op)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    OpError::not_allowed(format!(
        "此主机未允许 {domain}.{name}（在 helper.toml 的 [{domain}] allow 中开启）"
    ))
}

async fn hello(ctx: &Ctx) -> Value {
    let c = &ctx.cfg;
    json!({
        "v": VERSION,
        "version": env!("CARGO_PKG_VERSION"),
        "dry_run": c.dry_run,
        "confirm_secs": c.confirm_secs,
        "domains": {
            "docker": { "enabled": c.docker.enabled, "allow": c.docker.allow },
            "nginx": {
                "enabled": c.nginx.enabled,
                "allow": c.nginx.allow,
                "site_roots": c.nginx.site_roots,
                "cert_paths": c.nginx.cert_paths,
                "runtime": c.nginx.runtime.as_str(),
                "acme": {
                    "enabled": c.nginx.acme.enabled,
                    "staging": c.nginx.acme.directory.is_none() && c.nginx.acme.staging,
                    "custom_directory": c.nginx.acme.directory.is_some(),
                    "renew_days": c.nginx.acme.renew_days,
                },
            },
            "firewall": {
                "enabled": c.firewall.enabled,
                "allow": c.firewall.allow,
                "backend": if c.firewall.enabled { firewall::backend(c).await } else { None },
            },
            "ssh": { "enabled": c.ssh.enabled, "allow": c.ssh.allow },
        }
    })
}

/// Routes one authenticated request.
pub async fn dispatch(ctx: &Arc<Ctx>, call_name: &str, call: Call<'_>) -> OpResult<Value> {
    let (domain, op) = call_name.split_once('.').unwrap_or((call_name, ""));
    match domain {
        "hello" => Ok(hello(ctx).await),
        "pending" => {
            #[derive(serde::Deserialize)]
            struct Id {
                id: String,
            }
            match op {
                "list" => Ok(json!(ctx.pending.list().await)),
                "confirm" => {
                    let a: Id = call.args()?;
                    let v = ctx.pending.confirm(&a.id).await?;
                    call.log.line(format!("已确认：{}", v.summary));
                    Ok(json!(v))
                }
                "revert" => {
                    let a: Id = call.args()?;
                    let v = ctx.pending.revert(&a.id).await?;
                    call.log.line(format!("已撤销：{}", v.summary));
                    Ok(json!(v))
                }
                _ => Err(OpError::new(
                    ErrorCode::Unsupported,
                    format!("unknown call {call_name}"),
                )),
            }
        }
        "docker" => docker::handle(ctx, op, call).await,
        "nginx" => nginx::handle(ctx, op, call).await,
        "firewall" => firewall::handle(ctx, op, call).await,
        "ssh" => ssh::handle(ctx, op, call).await,
        _ => Err(OpError::new(
            ErrorCode::Unsupported,
            format!("unknown call {call_name}"),
        )),
    }
}

// ---------------------------------------------------------------- server

pub async fn serve(cfg: HelperConfig) -> Result<()> {
    let secret = crate::config::secret(&cfg.secret_env).with_context(|| {
        format!(
            "{} is not set; the helper refuses to start without a shared secret",
            cfg.secret_env
        )
    })?;
    if secret.len() < 16 {
        bail!("{} must be at least 16 characters", cfg.secret_env);
    }
    let socket = cfg.socket.clone();
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)
        .with_context(|| format!("binding {}", socket.display()))?;
    {
        // access is enforced by peer uid + secret; the mode just lets the service user connect
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
    }
    let ctx = Ctx::new(cfg)?;
    ctx.pending.recover().await;
    if ctx.cfg.nginx.enabled
        && ctx.cfg.nginx.acme.enabled
        && ctx.cfg.nginx.allow.contains(&config::NginxOp::Cert)
    {
        tokio::spawn(nginx_cert::renew_loop(ctx.clone()));
    }
    tracing::info!(
        "ops helper on {} (docker={} nginx={} firewall={} ssh={}{})",
        socket.display(),
        ctx.cfg.docker.enabled,
        ctx.cfg.nginx.enabled,
        ctx.cfg.firewall.enabled,
        ctx.cfg.ssh.enabled,
        if ctx.cfg.dry_run { ", dry run" } else { "" }
    );
    let secret: Arc<str> = secret.into();
    loop {
        let (stream, _) = listener.accept().await?;
        let uid = stream.peer_cred().map(|c| c.uid()).ok();
        let ctx = ctx.clone();
        let secret = secret.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, uid, ctx, &secret).await {
                tracing::warn!("helper connection: {e:#}");
            }
        });
    }
}

fn wire(r: &Reply) -> String {
    let mut s = serde_json::to_string(r).unwrap_or_default();
    s.push('\n');
    s
}

async fn read_request(r: tokio::net::unix::OwnedReadHalf) -> Result<Option<String>> {
    let mut buf = Vec::new();
    let mut rd = BufReader::new(r).take(MAX_LINE as u64 + 1);
    let n = tokio::time::timeout(Duration::from_secs(10), rd.read_until(b'\n', &mut buf))
        .await
        .context("request timed out")??;
    if n == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_LINE {
        bail!("request too large");
    }
    Ok(Some(String::from_utf8(buf)?.trim_end().to_string()))
}

async fn handle(
    stream: tokio::net::UnixStream,
    uid: Option<u32>,
    ctx: Arc<Ctx>,
    secret: &str,
) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let refuse = |code, message: String| wire(&Reply::Error { code, message });
    if !uid.is_some_and(|u| u == 0 || ctx.cfg.allowed_uids.contains(&u)) {
        tracing::warn!("helper: refused peer uid {uid:?}");
        w.write_all(refuse(ErrorCode::Unauthorized, "peer not allowed".into()).as_bytes())
            .await?;
        return Ok(());
    }
    let line = match read_request(r).await {
        Ok(Some(l)) => l,
        Ok(None) => return Ok(()),
        Err(e) => {
            w.write_all(refuse(ErrorCode::Invalid, format!("{e:#}")).as_bytes())
                .await?;
            return Ok(());
        }
    };
    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            w.write_all(refuse(ErrorCode::Invalid, format!("bad request: {e}")).as_bytes())
                .await?;
            return Ok(());
        }
    };
    if req.v != VERSION {
        w.write_all(
            refuse(
                ErrorCode::Unsupported,
                format!("protocol v{} not supported", req.v),
            )
            .as_bytes(),
        )
        .await?;
        return Ok(());
    }
    if !ct_eq(req.auth.as_bytes(), secret.as_bytes()) {
        tracing::warn!("helper: wrong secret from uid {uid:?} for {}", req.call);
        w.write_all(refuse(ErrorCode::Unauthorized, "bad secret".into()).as_bytes())
            .await?;
        return Ok(());
    }
    let dry_run = req.dry_run || ctx.cfg.dry_run;
    let quiet = req.call == "hello" || req.call.ends_with(".list") || is_query(&req.call);
    if !quiet {
        // the helper's own audit trail (journald), independent of the daemon's database
        tracing::info!(
            target: "helper::audit",
            "uid={uid:?} via={} remote={:?} job={:?} call={} dry_run={dry_run}",
            req.actor.via,
            req.actor.remote,
            req.actor.job,
            req.call
        );
    }
    // the work runs on even if the client goes away; output goes to it while it listens
    let (tx, mut rx) = mpsc::unbounded_channel::<Reply>();
    let log = Log {
        tx: tx.clone(),
        call: req.call.clone().into(),
    };
    tokio::spawn(async move {
        let call = Call {
            args: &req.args,
            dry_run,
            actor: &req.actor,
            log: &log,
        };
        // a panic in a handler must still produce a terminal line
        let fut = std::panic::AssertUnwindSafe(dispatch(&ctx, &req.call, call));
        let res = futures::FutureExt::catch_unwind(fut).await;
        let reply = match res {
            Ok(Ok(data)) => Reply::Result { data },
            Ok(Err(e)) => {
                if !quiet {
                    tracing::warn!(target: "helper::audit", "call={} failed: {}", req.call, e.message);
                }
                Reply::Error {
                    code: e.code,
                    message: e.message,
                }
            }
            Err(_) => Reply::Error {
                code: ErrorCode::Failed,
                message: "helper task panicked".into(),
            },
        };
        let _ = tx.send(reply);
    });
    while let Some(r) = rx.recv().await {
        let terminal = !matches!(r, Reply::Log { .. });
        if w.write_all(wire(&r).as_bytes()).await.is_err() {
            while rx.recv().await.is_some() {}
            break;
        }
        if terminal {
            break;
        }
    }
    Ok(())
}

/// Read-only calls (not written to the audit journal).
pub fn is_query(call: &str) -> bool {
    matches!(
        call,
        "hello"
            | "pending.list"
            | "docker.containers"
            | "docker.images"
            | "docker.volumes"
            | "docker.networks"
            | "nginx.sites"
            | "nginx.files"
            | "nginx.file"
            | "nginx.site_get"
            | "nginx.status"
            | "nginx.versions"
            | "nginx.log_tail"
            | "firewall.status"
            | "ssh.config"
            | "ssh.keys"
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ops::client;

    pub(crate) async fn spawn_helper(
        mut cfg: HelperConfig,
    ) -> (std::path::PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("h.sock");
        cfg.socket = socket.clone();
        cfg.state_dir = dir.path().join("state");
        // SAFETY: unique variable name for these tests.
        unsafe { std::env::set_var("TSM_TEST_HELPER_SECRET", "0123456789abcdef-test") };
        cfg.secret_env = "TSM_TEST_HELPER_SECRET".into();
        tokio::spawn(serve(cfg));
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (socket, dir)
    }

    fn base_cfg() -> HelperConfig {
        let me = unsafe { libc::getuid() };
        toml::from_str(&format!("allowed_uids = [{me}]\ndry_run = true")).unwrap()
    }

    #[tokio::test]
    async fn v2_round_trip_auth_and_legacy_refusal() {
        let mut cfg = base_cfg();
        cfg.nginx.enabled = true;
        let (socket, _dir) = spawn_helper(cfg).await;
        let secret = "0123456789abcdef-test";

        let hello = client::call_raw(
            &socket,
            secret,
            "hello",
            json!({}),
            false,
            Actor::default(),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(hello["v"], 2);
        assert_eq!(hello["dry_run"], true);
        assert_eq!(hello["domains"]["nginx"]["enabled"], true);
        assert_eq!(hello["domains"]["docker"]["enabled"], false);

        // wrong secret
        let e = client::call_raw(
            &socket,
            "wrong-secret-xxxxxxxx",
            "hello",
            json!({}),
            false,
            Actor::default(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Unauthorized);

        // a domain that is off
        let e = client::call_raw(
            &socket,
            secret,
            "docker.images",
            json!({}),
            false,
            Actor::default(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotAllowed);

        // an enabled domain with an empty allow list is read-only
        let e = client::call_raw(
            &socket,
            secret,
            "nginx.reload",
            json!({}),
            false,
            Actor::default(),
            |_| {},
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotAllowed, "{e}");

        // a legacy updater request must not be accepted by the v2 socket
        let mut s = tokio::net::UnixStream::connect(&socket).await.unwrap();
        s.write_all(b"{\"op\":\"refresh\"}\n").await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert!(out.contains("\"error\""), "{out}");

        // oversized request
        let mut s = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let big = vec![b'a'; MAX_LINE + 10];
        let _ = s.write_all(&big).await;
        let _ = s.write_all(b"\n").await;
        let mut out = String::new();
        let _ = s.read_to_string(&mut out).await;
        assert!(out.contains("too large") || out.is_empty(), "{out}");
    }

    #[tokio::test]
    async fn legacy_request_to_v2_helper_is_refused_by_old_updater_shape() {
        // A v2 envelope has no `op`, so the legacy updater rejects it instead of running apt.
        let v2 = serde_json::to_string(&Request {
            v: 2,
            auth: "x".into(),
            call: "docker.restart".into(),
            args: json!({}),
            dry_run: false,
            actor: Actor::default(),
        })
        .unwrap();
        assert!(serde_json::from_str::<crate::updater::Request>(&v2).is_err());
    }
}
