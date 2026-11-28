//! Where nginx runs and how to drive it: the host binary (systemd unit or plain process) or
//! the Docker container created by `nginx.install`. The config always lives in `nginx.root` on
//! the host (bind-mounted into the container at the same path), so everything that edits files
//! is runtime-agnostic; only running `nginx`, reloading and starting/stopping differ.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use super::config::{NginxOp, NginxRuntime};
use super::{Call, Ctx, Log, exec, nginx_docker, nginx_pkg};
use crate::ops::proto::{OpError, OpResult};

const UNIT: &str = "nginx.service";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runtime {
    Host(PathBuf),
    Docker(String),
    None,
}

impl Runtime {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Host(_) => "host",
            Self::Docker(_) => "docker",
            Self::None => "none",
        }
    }
}

/// The host nginx binary, when it exists.
pub fn host_binary(ctx: &Ctx) -> Option<PathBuf> {
    crate::sandbox::which(&ctx.cfg.nginx.binary)
}

pub async fn detect(ctx: &Ctx) -> Runtime {
    let n = &ctx.cfg.nginx;
    let docker = || async {
        nginx_docker::container_exists(ctx)
            .await
            .then(|| Runtime::Docker(n.docker.container.clone()))
    };
    match n.runtime {
        NginxRuntime::Host => host_binary(ctx).map_or(Runtime::None, Runtime::Host),
        NginxRuntime::Docker => docker().await.unwrap_or(Runtime::None),
        NginxRuntime::Auto => match docker().await {
            Some(r) => r,
            None => host_binary(ctx).map_or(Runtime::None, Runtime::Host),
        },
    }
}

fn not_installed() -> OpError {
    OpError::failed("未检测到 nginx（宿主机上没有 nginx 命令，也没有面板创建的 nginx 容器）")
}

/// Runs `nginx <args>` where nginx runs. A stopped container is an error.
pub async fn run_nginx(ctx: &Ctx, args: &[&str], timeout: Duration) -> OpResult<exec::Output> {
    match detect(ctx).await {
        Runtime::Host(bin) => {
            let mut argv = vec![bin.to_string_lossy().into_owned()];
            argv.extend(args.iter().map(|a| a.to_string()));
            exec::run(&argv, timeout).await.map_err(OpError::from)
        }
        Runtime::Docker(c) => {
            let mut cmd = vec!["nginx".to_string()];
            cmd.extend(args.iter().map(|a| a.to_string()));
            nginx_docker::exec(ctx, &c, cmd, timeout).await
        }
        Runtime::None => Err(not_installed()),
    }
}

fn echo(log: &Log, args: &[&str], out: &exec::Output) {
    log.line(format!("$ nginx {}", args.join(" ")));
    for l in out.stdout.lines().chain(out.stderr.lines()) {
        if !l.trim().is_empty() {
            log.line(l.to_string());
        }
    }
    if !out.ok() {
        log.line(format!("（退出码 {}）", out.code));
    }
}

/// `nginx -t`.
pub async fn test(ctx: &Ctx, log: &Log) -> OpResult<exec::Output> {
    let out = run_nginx(ctx, &["-t"], Duration::from_secs(30)).await?;
    echo(log, &["-t"], &out);
    Ok(out)
}

pub async fn reload(ctx: &Ctx, log: &Log) -> OpResult<()> {
    let out = match detect(ctx).await {
        Runtime::Host(bin) => {
            let argv = if exec::unit_active(UNIT).await {
                exec::argv(&["systemctl", "reload", UNIT])
            } else {
                vec![
                    bin.to_string_lossy().into_owned(),
                    "-s".into(),
                    "reload".into(),
                ]
            };
            exec::run_logged(log, &argv, Duration::from_secs(60)).await?
        }
        Runtime::Docker(_) => {
            let out = run_nginx(ctx, &["-s", "reload"], Duration::from_secs(60)).await?;
            echo(log, &["-s", "reload"], &out);
            out
        }
        Runtime::None => return Err(not_installed()),
    };
    if !out.ok() {
        return Err(OpError::failed(format!("重新加载失败：{}", out.message())));
    }
    Ok(())
}

/// nginx version as (major, minor, patch); cached until [`forget_version`].
pub async fn version(ctx: &Ctx) -> Option<(u32, u32, u32)> {
    if let Some(v) = *ctx.nginx_version.lock().unwrap_or_else(|e| e.into_inner()) {
        return v;
    }
    let v = run_nginx(ctx, &["-v"], Duration::from_secs(10))
        .await
        .ok()
        .and_then(|o| parse_version(&format!("{}{}", o.stderr, o.stdout)));
    *ctx.nginx_version.lock().unwrap_or_else(|e| e.into_inner()) = Some(v);
    v
}

pub fn forget_version(ctx: &Ctx) {
    *ctx.nginx_version.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let v = s.split("nginx/").nth(1)?;
    let mut it = v
        .split(|c: char| !c.is_ascii_digit())
        .map(|x| x.parse::<u32>());
    Some((it.next()?.ok()?, it.next()?.ok()?, it.next()?.ok()?))
}

/// What `nginx -V` says: version, the "built with" line and the module list.
#[derive(Debug, Default, PartialEq)]
pub struct Build {
    pub version: Option<String>,
    pub build: Option<String>,
    pub modules: Vec<String>,
}

pub fn parse_build(text: &str) -> Build {
    let mut b = Build {
        version: parse_version(text).map(|(a, m, p)| format!("{a}.{m}.{p}")),
        ..Default::default()
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("built with") {
            b.build = Some(line.to_string());
        }
        if let Some(args) = line.strip_prefix("configure arguments:") {
            for a in args.split_whitespace() {
                let m = if let Some(m) = a.strip_prefix("--with-") {
                    let named = ["stream", "mail", "compat", "threads", "file-aio"].contains(&m);
                    // --with-cc-opt=..., --with-openssl=... are build options, not modules
                    if m.contains('=') || !(m.ends_with("_module") || named) {
                        continue;
                    }
                    m
                } else if let Some(p) = a
                    .strip_prefix("--add-dynamic-module=")
                    .or_else(|| a.strip_prefix("--add-module="))
                {
                    match p.split('/').rfind(|s| !s.is_empty() && *s != "nginx") {
                        Some(n) => n,
                        None => continue,
                    }
                } else {
                    continue;
                };
                if !b.modules.iter().any(|x| x == m) {
                    b.modules.push(m.to_string());
                }
            }
        }
    }
    b
}

/// Number of worker processes on the host (by process title).
fn host_workers() -> Option<u64> {
    let dir = std::fs::read_dir("/proc").ok()?;
    let mut n = 0;
    for e in dir.flatten() {
        if !e
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
        {
            continue;
        }
        if let Ok(c) = std::fs::read(e.path().join("cmdline"))
            && String::from_utf8_lossy(&c).starts_with("nginx: worker process")
        {
            n += 1;
        }
    }
    Some(n)
}

/// Host master process alive (pid file), for nginx not run by systemd.
fn host_pid_alive() -> bool {
    ["/run/nginx.pid", "/var/run/nginx.pid"].iter().any(|p| {
        std::fs::read_to_string(p)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .is_some_and(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
    })
}

async fn unit_started_at() -> Option<i64> {
    let o = exec::run(
        &exec::argv(&[
            "systemctl",
            "show",
            "--timestamp=unix",
            "-p",
            "ActiveEnterTimestamp",
            "--value",
            UNIT,
        ]),
        Duration::from_secs(10),
    )
    .await
    .ok()?;
    o.stdout.trim().strip_prefix('@')?.parse().ok()
}

/// Read-only overview for the service panel.
pub async fn status(ctx: &Ctx) -> Value {
    let rt = detect(ctx).await;
    let n = &ctx.cfg.nginx;
    let docker_available = nginx_docker::available(ctx).await;
    let mut v = json!({
        "runtime": rt.name(),
        "configured_runtime": n.runtime.as_str(),
        "installed": rt != Runtime::None,
        "running": false,
        "version": null,
        "modules": [],
        "build": null,
        "workers": null,
        "started_at": null,
        "service": null,
        "container": null,
        "package": null,
        "previous_image": nginx_docker::previous_image(ctx),
        "install_blockers": [],
        "docker_available": docker_available,
    });
    let build = match &rt {
        Runtime::None => {
            v["install_blockers"] = json!(nginx_docker::install_blockers(ctx).await);
            return v;
        }
        Runtime::Host(_) => {
            let unit = exec::unit_loaded(UNIT).await;
            let running = if unit {
                exec::unit_active(UNIT).await
            } else {
                host_pid_alive()
            };
            v["running"] = json!(running);
            if unit {
                v["service"] = json!(UNIT);
                if running {
                    v["started_at"] = json!(unit_started_at().await);
                }
            }
            if running {
                v["workers"] = json!(host_workers());
            }
            v["package"] = json!(nginx_pkg::info().await);
            run_nginx(ctx, &["-V"], Duration::from_secs(10)).await.ok()
        }
        Runtime::Docker(c) => {
            let info = nginx_docker::inspect(ctx, c).await;
            let running = info.as_ref().is_some_and(|i| i.running);
            v["running"] = json!(running);
            if let Some(i) = &info {
                v["container"] =
                    json!({ "name": c, "id": i.id, "image": i.image, "state": i.state });
                v["started_at"] = json!(i.started_at);
            }
            if running {
                v["workers"] = json!(nginx_docker::workers(ctx, c).await);
                run_nginx(ctx, &["-V"], Duration::from_secs(10)).await.ok()
            } else {
                None
            }
        }
    };
    if let Some(o) = build {
        let b = parse_build(&format!("{}{}", o.stderr, o.stdout));
        v["version"] = json!(b.version);
        v["build"] = json!(b.build);
        v["modules"] = json!(b.modules);
    } else if let Runtime::Docker(_) = rt {
        // stopped container: the image tag is the best guess
        v["version"] = json!(
            v["container"]["image"]
                .as_str()
                .and_then(|i| i.rsplit_once(':'))
                .map(|(_, t)| t.to_string())
        );
    }
    v
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    fn label(self) -> &'static str {
        match self {
            Self::Start => "启动",
            Self::Stop => "停止",
            Self::Restart => "重启",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceArgs {
    action: Action,
}

/// Start / stop / restart. Starting needs a config that passes `nginx -t`.
pub async fn service(ctx: &Ctx, a: ServiceArgs, call: &Call<'_>) -> OpResult<Value> {
    super::nginx::allow(ctx, NginxOp::Service)?;
    let rt = detect(ctx).await;
    if rt == Runtime::None {
        return Err(not_installed());
    }
    let label = a.action.label();
    call.log.line(format!("{label} nginx（{}）", rt.name()));
    if a.action != Action::Stop {
        // a running container can test itself; a stopped one is tested with a one-off copy
        let t = match &rt {
            Runtime::Docker(c) if !nginx_docker::running(ctx, c).await => {
                nginx_docker::test_stopped(ctx, c, call.log).await?
            }
            _ => test(ctx, call.log).await?,
        };
        if !t.ok() {
            return Err(OpError::failed(format!(
                "配置检查未通过，未{label}：\n{}",
                t.message()
            )));
        }
    }
    if call.dry_run {
        call.log.line("（演练模式：未实际执行）");
        return Ok(json!({ "dry_run": true }));
    }
    match &rt {
        Runtime::Host(bin) => {
            let argv = if exec::unit_loaded(UNIT).await {
                exec::argv(&[
                    "systemctl",
                    match a.action {
                        Action::Start => "start",
                        Action::Stop => "stop",
                        Action::Restart => "restart",
                    },
                    UNIT,
                ])
            } else {
                let b = bin.to_string_lossy().into_owned();
                match a.action {
                    Action::Start => vec![b],
                    Action::Stop => vec![b, "-s".into(), "quit".into()],
                    Action::Restart => {
                        let quit = vec![b.clone(), "-s".into(), "quit".into()];
                        let _ = exec::run_logged(call.log, &quit, Duration::from_secs(30)).await?;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        vec![b]
                    }
                }
            };
            let out = exec::run_logged(call.log, &argv, Duration::from_secs(90)).await?;
            if !out.ok() {
                return Err(OpError::failed(format!("{label}失败：{}", out.message())));
            }
        }
        Runtime::Docker(c) => nginx_docker::container_action(ctx, c, a.action, call.log).await?,
        Runtime::None => unreachable!(),
    }
    if a.action != Action::Stop {
        super::nginx::probe(ctx, call.log).await?;
    }
    call.log.line("完成");
    Ok(json!({ "action": label }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogArgs {
    file: LogFile,
    /// number or numeric string (dashboard reads pass query strings)
    #[serde(default)]
    lines: Option<Value>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum LogFile {
    Error,
    Access,
}

/// Last lines of error.log / access.log (at most 1000 lines from the last 512 KiB).
pub fn log_tail(ctx: &Ctx, a: LogArgs) -> OpResult<Value> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX: u64 = 512 * 1024;
    let name = match a.file {
        LogFile::Error => "error.log",
        LogFile::Access => "access.log",
    };
    let path = ctx.cfg.nginx.log_dir.join(name);
    let lines = match &a.lines {
        None => 200,
        Some(Value::Number(n)) => n.as_u64().unwrap_or(200) as usize,
        Some(Value::String(t)) => t
            .parse()
            .map_err(|_| OpError::invalid(format!("lines 应为数字：{t:?}")))?,
        Some(_) => return Err(OpError::invalid("lines 应为数字")),
    }
    .clamp(1, 1000);
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({ "path": path, "lines": [], "truncated": false }));
        }
        Err(e) => return Err(OpError::failed(format!("读取 {}：{e}", path.display()))),
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(MAX);
    f.seek(SeekFrom::Start(start))
        .map_err(|e| OpError::failed(e.to_string()))?;
    let mut buf = Vec::new();
    f.take(MAX)
        .read_to_end(&mut buf)
        .map_err(|e| OpError::failed(e.to_string()))?;
    let text = String::from_utf8_lossy(&buf);
    let mut all: Vec<&str> = text.lines().collect();
    if start > 0 && !all.is_empty() {
        all.remove(0); // partial first line
    }
    let truncated = start > 0 || all.len() > lines;
    let tail: Vec<&str> = all[all.len().saturating_sub(lines)..].to_vec();
    Ok(json!({ "path": path, "lines": tail, "truncated": truncated }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nginx_dash_v() {
        let t = "nginx version: nginx/1.27.3\nbuilt by gcc 12.2.0 (Debian 12.2.0-14)\nbuilt with OpenSSL 3.0.15 3 Sep 2024\nTLS SNI support enabled\nconfigure arguments: --prefix=/etc/nginx --with-cc-opt='-g -O2' --with-compat --with-threads --with-http_ssl_module --with-http_v2_module --with-stream --with-stream_ssl_module --with-openssl=/x --add-dynamic-module=/build/njs/nginx\n";
        let b = parse_build(t);
        assert_eq!(b.version.as_deref(), Some("1.27.3"));
        assert_eq!(
            b.build.as_deref(),
            Some("built with OpenSSL 3.0.15 3 Sep 2024")
        );
        assert_eq!(
            b.modules,
            [
                "compat",
                "threads",
                "http_ssl_module",
                "http_v2_module",
                "stream",
                "stream_ssl_module",
                "njs"
            ]
        );
        assert_eq!(
            parse_version("nginx version: nginx/1.22.1\n"),
            Some((1, 22, 1))
        );
        assert_eq!(parse_version("garbage"), None);
    }

    #[test]
    fn log_tail_reads_last_lines() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg: crate::helper::HelperConfig = toml::from_str("allowed_uids = []").unwrap();
        cfg.state_dir = d.path().join("state");
        cfg.nginx.log_dir = d.path().to_path_buf();
        let ctx = Ctx::new(cfg).unwrap();
        let body: String = (1..=50).map(|i| format!("line {i}\n")).collect();
        std::fs::write(d.path().join("error.log"), body).unwrap();
        let a: LogArgs = serde_json::from_value(json!({ "file": "error", "lines": "3" })).unwrap();
        let v = log_tail(&ctx, a).unwrap();
        assert_eq!(v["lines"], json!(["line 48", "line 49", "line 50"]));
        assert_eq!(v["truncated"], true);
        let a: LogArgs = serde_json::from_value(json!({ "file": "access" })).unwrap();
        assert_eq!(log_tail(&ctx, a).unwrap()["lines"], json!([]));
        assert!(serde_json::from_value::<LogArgs>(json!({ "file": "../etc/passwd" })).is_err());
    }
}
