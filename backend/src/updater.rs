//! Optional package update helper (`tsmonitor updater`). It is the only part of TServerMonitor
//! that changes the host, so it is a separate process with its own root-owned config and
//! systemd unit; the monitoring daemon stays unprivileged and talks to it over a Unix socket.
//!
//! * Only a fixed set of operations exists (refresh index, upgrade security / all / named
//!   packages) for apt or dnf. Commands are built from argv arrays, never through a shell, and
//!   package names are validated.
//! * Only peers whose uid is listed in `allowed_uids` (and root) may connect.
//! * One job at a time; the job keeps running if the client disconnects.
//! * `dry_run = true` prints the commands instead of running them.
//!
//! Protocol: newline-delimited JSON. Client sends `{"op": "...", "packages": [...]}`; helper
//! replies with `{"type":"log","line":"..."}` lines and a final `{"type":"done","ok":bool,"exit_code":n}`,
//! or `{"type":"error","message":"..."}`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

pub const DEFAULT_SOCKET: &str = "/run/tsmonitor-updater/updater.sock";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Refresh,
    UpgradeSecurity,
    UpgradeAll,
    UpgradePackages,
}

impl Op {
    pub fn label(self) -> &'static str {
        match self {
            Op::Refresh => "刷新软件包索引",
            Op::UpgradeSecurity => "安装安全更新",
            Op::UpgradeAll => "升级全部软件包",
            Op::UpgradePackages => "升级选中的软件包",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Manager {
    Apt,
    Dnf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdaterConfig {
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    /// uids allowed to connect besides root (the tsmonitor service user).
    pub allowed_uids: Vec<u32>,
    /// apt or dnf; detected when omitted.
    #[serde(default)]
    pub manager: Option<Manager>,
    /// Operations this host permits.
    #[serde(default = "default_ops")]
    pub allow: Vec<Op>,
    /// Print the commands instead of running them.
    #[serde(default)]
    pub dry_run: bool,
}

fn default_socket() -> PathBuf {
    DEFAULT_SOCKET.into()
}

fn default_ops() -> Vec<Op> {
    vec![
        Op::Refresh,
        Op::UpgradeSecurity,
        Op::UpgradeAll,
        Op::UpgradePackages,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub op: Op,
    #[serde(default)]
    pub packages: Vec<String>,
}

const MAX_PACKAGES: usize = 200;

pub fn valid_package(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b".+_:-".contains(c))
}

pub fn validate(req: &Request, allow: &[Op]) -> Result<()> {
    if !allow.contains(&req.op) {
        bail!("operation {:?} is not allowed on this host", req.op);
    }
    match req.op {
        Op::UpgradePackages => {
            if req.packages.is_empty() || req.packages.len() > MAX_PACKAGES {
                bail!("1..{MAX_PACKAGES} package names required");
            }
            if let Some(bad) = req.packages.iter().find(|p| !valid_package(p)) {
                bail!("invalid package name {bad:?}");
            }
        }
        _ if !req.packages.is_empty() => bail!("this operation takes no package names"),
        _ => {}
    }
    Ok(())
}

/// Command lines (argv) for an operation. `security` = apt packages from the security pocket.
pub fn commands(m: Manager, req: &Request, security: &[String]) -> Result<Vec<Vec<String>>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let with = |mut base: Vec<String>, pkgs: &[String]| {
        base.push("--".into());
        base.extend(pkgs.iter().cloned());
        base
    };
    let apt_install = s(&[
        "apt-get",
        "-y",
        "-o",
        "Dpkg::Options::=--force-confdef",
        "-o",
        "Dpkg::Options::=--force-confold",
        "--only-upgrade",
        "install",
    ]);
    Ok(match (m, req.op) {
        (Manager::Apt, Op::Refresh) => vec![s(&["apt-get", "update"])],
        (Manager::Apt, Op::UpgradeAll) => vec![s(&[
            "apt-get",
            "-y",
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
            "upgrade",
        ])],
        (Manager::Apt, Op::UpgradeSecurity) => {
            if security.is_empty() {
                Vec::new()
            } else {
                vec![with(apt_install, security)]
            }
        }
        (Manager::Apt, Op::UpgradePackages) => vec![with(apt_install, &req.packages)],
        (Manager::Dnf, Op::Refresh) => vec![s(&["dnf", "-y", "makecache"])],
        (Manager::Dnf, Op::UpgradeAll) => vec![s(&["dnf", "-y", "upgrade"])],
        (Manager::Dnf, Op::UpgradeSecurity) => vec![s(&["dnf", "-y", "upgrade", "--security"])],
        (Manager::Dnf, Op::UpgradePackages) => {
            vec![with(s(&["dnf", "-y", "upgrade"]), &req.packages)]
        }
    })
}

fn detect() -> Option<Manager> {
    if crate::sandbox::which("apt-get").is_some() {
        Some(Manager::Apt)
    } else if crate::sandbox::which("dnf").is_some() {
        Some(Manager::Dnf)
    } else {
        None
    }
}

// ---------------------------------------------------------------- helper (server)

pub async fn serve(cfg: UpdaterConfig) -> Result<()> {
    let manager = cfg
        .manager
        .or_else(detect)
        .context("neither apt-get nor dnf found; set manager in the updater config")?;
    if let Some(dir) = cfg.socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(&cfg.socket);
    let listener = tokio::net::UnixListener::bind(&cfg.socket)
        .with_context(|| format!("binding {}", cfg.socket.display()))?;
    // access is enforced by peer uid below; the mode just lets the service user connect
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(0o666))?;
    }
    tracing::info!(
        "package updater on {} ({manager:?}{})",
        cfg.socket.display(),
        if cfg.dry_run { ", dry run" } else { "" }
    );
    let cfg = Arc::new(cfg);
    let busy = Arc::new(AtomicBool::new(false));
    loop {
        let (stream, _) = listener.accept().await?;
        let uid = stream.peer_cred().map(|c| c.uid()).ok();
        let cfg = cfg.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, uid, cfg, manager, busy).await {
                tracing::warn!("updater connection: {e:#}");
            }
        });
    }
}

async fn handle(
    stream: tokio::net::UnixStream,
    uid: Option<u32>,
    cfg: Arc<UpdaterConfig>,
    manager: Manager,
    busy: Arc<AtomicBool>,
) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let reply = |v: Value| {
        let mut s = v.to_string();
        s.push('\n');
        s
    };
    if !uid.is_some_and(|u| u == 0 || cfg.allowed_uids.contains(&u)) {
        tracing::warn!("updater: refused peer uid {uid:?}");
        w.write_all(reply(json!({ "type": "error", "message": "peer not allowed" })).as_bytes())
            .await?;
        return Ok(());
    }
    let mut lines = BufReader::new(r).lines();
    let Some(line) = lines.next_line().await? else {
        return Ok(());
    };
    let req: Request = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            w.write_all(
                reply(json!({ "type": "error", "message": format!("bad request: {e}") }))
                    .as_bytes(),
            )
            .await?;
            return Ok(());
        }
    };
    if let Err(e) = validate(&req, &cfg.allow) {
        w.write_all(reply(json!({ "type": "error", "message": format!("{e:#}") })).as_bytes())
            .await?;
        return Ok(());
    }
    if busy.swap(true, Ordering::SeqCst) {
        w.write_all(
            reply(json!({ "type": "error", "message": "another update job is running" }))
                .as_bytes(),
        )
        .await?;
        return Ok(());
    }
    tracing::info!(
        "updater: {:?} {:?} requested by uid {uid:?}",
        req.op,
        req.packages
    );
    // the job runs on even if the client goes away; output goes to the client while it listens
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    let job_cfg = cfg.clone();
    tokio::spawn(async move {
        let done = run_job(manager, &req, job_cfg.dry_run, &tx).await;
        let _ = tx.send(done);
        busy.store(false, Ordering::SeqCst);
    });
    while let Some(v) = rx.recv().await {
        if w.write_all(reply(v).as_bytes()).await.is_err() {
            // client gone; drain so the job is not blocked
            while rx.recv().await.is_some() {}
            break;
        }
    }
    Ok(())
}

async fn run_job(
    manager: Manager,
    req: &Request,
    dry_run: bool,
    tx: &mpsc::UnboundedSender<Value>,
) -> Value {
    let log = |line: String| {
        tracing::info!(target: "updater", "{line}");
        let _ = tx.send(json!({ "type": "log", "line": line }));
    };
    let security = if manager == Manager::Apt && req.op == Op::UpgradeSecurity {
        let out = tokio::process::Command::new("apt-get")
            .args(["-s", "-o", "Debug::NoLocking=1", "upgrade"])
            .env("LC_ALL", "C")
            .output()
            .await;
        match out {
            Ok(o) => crate::collect::packages::parse_apt(&String::from_utf8_lossy(&o.stdout))
                .into_iter()
                .filter(|p| p.security)
                .map(|p| p.name)
                .collect(),
            Err(e) => {
                return json!({ "type": "done", "ok": false, "exit_code": -1, "message": format!("apt-get -s: {e}") });
            }
        }
    } else {
        Vec::new()
    };
    let cmds = match commands(manager, req, &security) {
        Ok(c) => c,
        Err(e) => {
            return json!({ "type": "done", "ok": false, "exit_code": -1, "message": format!("{e:#}") });
        }
    };
    if cmds.is_empty() {
        log("没有可安装的安全更新".into());
        return json!({ "type": "done", "ok": true, "exit_code": 0 });
    }
    for argv in cmds {
        log(format!("$ {}", argv.join(" ")));
        if dry_run {
            log("（演练模式：未实际执行）".into());
            continue;
        }
        let code = match exec(&argv, &log).await {
            Ok(c) => c,
            Err(e) => {
                log(format!("{e:#}"));
                -1
            }
        };
        if code != 0 {
            return json!({ "type": "done", "ok": false, "exit_code": code });
        }
    }
    json!({ "type": "done", "ok": true, "exit_code": 0 })
}

async fn exec(argv: &[String], log: &impl Fn(String)) -> Result<i32> {
    let mut child = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", argv[0]))?;
    let out = child.stdout.take().context("stdout")?;
    let err = child.stderr.take().context("stderr")?;
    let mut o = BufReader::new(out).lines();
    let mut e = BufReader::new(err).lines();
    let (mut o_done, mut e_done) = (false, false);
    while !(o_done && e_done) {
        tokio::select! {
            l = o.next_line(), if !o_done => match l? { Some(l) => log(l), None => o_done = true },
            l = e.next_line(), if !e_done => match l? { Some(l) => log(l), None => e_done = true },
        }
    }
    Ok(child.wait().await?.code().unwrap_or(-1))
}

pub fn load_config(path: &Path) -> Result<UpdaterConfig> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

// ---------------------------------------------------------------- daemon side (client)

/// Sends a request and calls `on_event` for every reply line until the helper closes.
pub async fn request(socket: &Path, req: &Request, mut on_event: impl FnMut(Value)) -> Result<()> {
    let stream = tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to the update helper at {}", socket.display()))?;
    let (r, mut w) = stream.into_split();
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    w.write_all(line.as_bytes()).await?;
    let mut lines = BufReader::new(r).lines();
    while let Some(l) = lines.next_line().await? {
        if let Ok(v) = serde_json::from_str::<Value>(&l) {
            on_event(v);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- jobs (daemon side)

const MAX_LOG: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Job {
    pub id: i64,
    pub op: String,
    #[sqlx(json)]
    pub packages: Vec<String>,
    pub status: String,
    pub exit_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[sqlx(default)]
    pub log: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
}

/// Jobs left running by a daemon restart: the helper may have finished them, we cannot know.
pub async fn close_stale_jobs(db: &crate::store::Db) -> Result<()> {
    sqlx::query(
        "UPDATE package_jobs SET status = 'unknown', finished_at = ? WHERE status = 'running'",
    )
    .bind(crate::model::now_ms())
    .execute(db)
    .await?;
    Ok(())
}

pub async fn list_jobs(db: &crate::store::Db) -> Result<Vec<Job>> {
    Ok(sqlx::query_as::<_, Job>(
        "SELECT id, op, packages, status, exit_code, NULL AS log, started_at, finished_at FROM package_jobs ORDER BY id DESC LIMIT 20",
    )
    .fetch_all(db)
    .await?)
}

pub async fn get_job(db: &crate::store::Db, id: i64) -> Result<Option<Job>> {
    Ok(sqlx::query_as::<_, Job>(
        "SELECT id, op, packages, status, exit_code, log, started_at, finished_at FROM package_jobs WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?)
}

pub fn helper_available(socket: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(socket).is_ok_and(|m| m.file_type().is_socket())
    }
    #[cfg(not(unix))]
    {
        let _ = socket;
        false
    }
}

/// Starts a job through the helper and streams its output over SSE. Returns the job id.
pub async fn start_job(state: &crate::state::Shared, req: Request) -> Result<i64> {
    use crate::model::{Event, now_ms};
    validate(&req, &default_ops()).map_err(|e| crate::settings::Invalid(format!("{e:#}")))?;
    let socket = state.cfg.packages.updater_socket.clone();
    if !helper_available(&socket) {
        return Err(crate::settings::Invalid(format!(
            "未安装或未启动更新助手（{}），只能查看更新列表",
            socket.display()
        ))
        .into());
    }
    let running: i64 =
        sqlx::query_scalar("SELECT count(*) FROM package_jobs WHERE status = 'running'")
            .fetch_one(&state.db)
            .await?;
    if running > 0 {
        return Err(crate::settings::Invalid("已有更新任务在运行".into()).into());
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO package_jobs (op, packages, status, started_at) VALUES (?, ?, 'running', ?) RETURNING id",
    )
    .bind(serde_json::to_value(req.op)?.as_str().unwrap_or_default())
    .bind(serde_json::to_string(&req.packages)?)
    .bind(now_ms())
    .fetch_one(&state.db)
    .await?;
    state.emit(Event::PackageJob {
        id,
        status: "running".into(),
        line: None,
    });
    let state = state.clone();
    tokio::spawn(async move {
        let mut log = String::new();
        let mut done: Option<(bool, i64)> = None;
        let res = request(&socket, &req, |v| match v["type"].as_str() {
            Some("log") => {
                let line = v["line"].as_str().unwrap_or_default().to_string();
                if log.len() < MAX_LOG {
                    log.push_str(&line);
                    log.push('\n');
                }
                state.emit(Event::PackageJob {
                    id,
                    status: "running".into(),
                    line: Some(line),
                });
            }
            Some("done") => {
                done = Some((
                    v["ok"].as_bool().unwrap_or(false),
                    v["exit_code"].as_i64().unwrap_or(-1),
                ));
                if let Some(m) = v["message"].as_str() {
                    log.push_str(m);
                    log.push('\n');
                }
            }
            Some("error") => {
                log.push_str(v["message"].as_str().unwrap_or("helper error"));
                log.push('\n');
                done = Some((false, -1));
            }
            _ => {}
        })
        .await;
        if let Err(e) = res {
            log.push_str(&format!("{e:#}\n"));
        }
        let (ok, code) = done.unwrap_or((false, -1));
        let status = if ok { "succeeded" } else { "failed" };
        if let Err(e) = sqlx::query("UPDATE package_jobs SET status = ?, exit_code = ?, log = ?, finished_at = ? WHERE id = ?")
            .bind(status)
            .bind(code)
            .bind(&log)
            .bind(now_ms())
            .bind(id)
            .execute(&state.db)
            .await
        {
            tracing::warn!("storing package job {id}: {e:#}");
        }
        state.emit(Event::PackageJob {
            id,
            status: status.into(),
            line: None,
        });
        crate::collect::packages::check(&state).await;
    });
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let c: UpdaterConfig =
            toml::from_str(include_str!("../../deploy/updater.example.toml")).unwrap();
        assert!(c.dry_run);
        assert!(!c.allow.contains(&Op::UpgradeAll));
    }

    #[test]
    fn package_names_and_ops_are_checked() {
        assert!(valid_package("libssl3"));
        assert!(valid_package("python3.11-dev"));
        assert!(valid_package("g++"));
        assert!(!valid_package("-o=evil"));
        assert!(!valid_package("a b"));
        assert!(!valid_package("$(reboot)"));
        let req = |op, packages: &[&str]| Request {
            op,
            packages: packages.iter().map(|s| s.to_string()).collect(),
        };
        assert!(validate(&req(Op::UpgradePackages, &["nginx"]), &default_ops()).is_ok());
        assert!(validate(&req(Op::UpgradePackages, &[]), &default_ops()).is_err());
        assert!(validate(&req(Op::UpgradePackages, &["--purge"]), &default_ops()).is_err());
        assert!(validate(&req(Op::Refresh, &["x"]), &default_ops()).is_err());
        assert!(validate(&req(Op::UpgradeAll, &[]), &[Op::Refresh]).is_err());
    }

    #[test]
    fn commands_never_mix_options_and_names() {
        let req = Request {
            op: Op::UpgradePackages,
            packages: vec!["nginx".into(), "openssl".into()],
        };
        let apt = commands(Manager::Apt, &req, &[]).unwrap();
        let argv = &apt[0];
        let sep = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &argv[sep + 1..],
            &["nginx".to_string(), "openssl".to_string()]
        );
        assert!(argv.contains(&"--only-upgrade".to_string()));
        let dnf = commands(Manager::Dnf, &req, &[]).unwrap();
        assert_eq!(dnf[0][..3], ["dnf", "-y", "upgrade"]);
        let none = commands(
            Manager::Apt,
            &Request {
                op: Op::UpgradeSecurity,
                packages: vec![],
            },
            &[],
        )
        .unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn socket_protocol_with_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("u.sock");
        let me = unsafe { libc::getuid() };
        let cfg = UpdaterConfig {
            socket: socket.clone(),
            allowed_uids: vec![me],
            manager: Some(Manager::Dnf),
            allow: vec![Op::Refresh, Op::UpgradePackages],
            dry_run: true,
        };
        tokio::spawn(serve(cfg));
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mut events = Vec::new();
        request(
            &socket,
            &Request {
                op: Op::UpgradePackages,
                packages: vec!["nginx".into()],
            },
            |v| events.push(v),
        )
        .await
        .unwrap();
        assert!(
            events.iter().any(|e| e["line"]
                .as_str()
                .is_some_and(|l| l.contains("dnf -y upgrade -- nginx"))),
            "{events:?}"
        );
        assert_eq!(events.last().unwrap()["type"], "done");
        assert_eq!(events.last().unwrap()["ok"], true);

        let mut refused = Vec::new();
        request(
            &socket,
            &Request {
                op: Op::UpgradeAll,
                packages: vec![],
            },
            |v| refused.push(v),
        )
        .await
        .unwrap();
        assert_eq!(refused[0]["type"], "error");
    }
}
