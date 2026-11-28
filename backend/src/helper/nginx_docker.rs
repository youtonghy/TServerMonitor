//! nginx as a Docker container managed by the helper (`nginx.install`, `nginx.upgrade`,
//! `nginx.rollback`). Unlike the Docker domain, this module creates containers and runs `exec`,
//! but only with one fixed shape: the configured nginx image, host networking, and bind mounts
//! of the nginx config (read-only, at the same path as on the host), the log directory, the
//! static site roots and certificate directories (read-only) plus `nginx.docker.binds` from
//! the root-owned helper config. Nothing here takes a path or an image from the caller except
//! a version tag.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use bollard::Docker;
use bollard::exec::{StartExecOptions, StartExecResults};
use bollard::models::{
    ContainerCreateBody, ExecConfig, HostConfig, RestartPolicy, RestartPolicyNameEnum,
};
use bollard::query_parameters::{
    CreateContainerOptionsBuilder, InspectContainerOptions, LogsOptionsBuilder,
    RemoveContainerOptionsBuilder, RenameContainerOptionsBuilder, RestartContainerOptionsBuilder,
    StartContainerOptions, StopContainerOptionsBuilder, TopOptions, WaitContainerOptions,
};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};

use super::config::{NginxOp, parse_bind};
use super::nginx_runtime::{self as rt, Action};
use super::{Call, Ctx, Log, exec};
use crate::ops::proto::{OpError, OpResult};

/// The config directory nginx images read; the host root is mounted here.
const ETC: &str = "/etc/nginx";
const LABEL: &str = "tsmonitor.nginx";
const STATE_FILE: &str = "nginx-docker.json";

fn engine(e: bollard::errors::Error) -> OpError {
    OpError::failed(format!("Docker：{e}"))
}

fn connect(ctx: &Ctx) -> OpResult<Docker> {
    super::docker::connect(ctx)
}

/// Short timeout for probes that run on every status / detection.
async fn quick<T>(f: impl std::future::Future<Output = T>) -> Option<T> {
    tokio::time::timeout(Duration::from_secs(5), f).await.ok()
}

pub async fn available(ctx: &Ctx) -> bool {
    let Ok(d) = connect(ctx) else { return false };
    quick(d.ping()).await.is_some_and(|r| r.is_ok())
}

pub async fn container_exists(ctx: &Ctx) -> bool {
    if !ctx.cfg.docker.socket.exists() {
        return false;
    }
    let Ok(d) = connect(ctx) else { return false };
    let name = &ctx.cfg.nginx.docker.container;
    quick(d.inspect_container(name, None::<InspectContainerOptions>))
        .await
        .is_some_and(|r| r.is_ok())
}

pub struct Info {
    pub id: String,
    pub image: String,
    pub state: String,
    pub running: bool,
    pub started_at: Option<i64>,
}

pub async fn inspect(ctx: &Ctx, name: &str) -> Option<Info> {
    let d = connect(ctx).ok()?;
    let i = quick(d.inspect_container(name, None::<InspectContainerOptions>))
        .await?
        .ok()?;
    let st = i.state.unwrap_or_default();
    let running = st.running.unwrap_or(false);
    Some(Info {
        id: i.id.unwrap_or_default().chars().take(12).collect(),
        image: i.config.and_then(|c| c.image).unwrap_or_default(),
        state: st.status.map(|s| s.to_string()).unwrap_or_default(),
        running,
        started_at: st
            .started_at
            .filter(|_| running)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|t| t.timestamp()),
    })
}

pub async fn running(ctx: &Ctx, name: &str) -> bool {
    inspect(ctx, name).await.is_some_and(|i| i.running)
}

pub async fn workers(ctx: &Ctx, name: &str) -> Option<u64> {
    let d = connect(ctx).ok()?;
    let top = quick(d.top_processes(name, None::<TopOptions>))
        .await?
        .ok()?;
    Some(
        top.processes
            .unwrap_or_default()
            .iter()
            .filter(|p| p.iter().any(|c| c.contains("nginx: worker process")))
            .count() as u64,
    )
}

/// Runs `cmd` in the running container.
pub async fn exec(
    ctx: &Ctx,
    name: &str,
    cmd: Vec<String>,
    timeout: Duration,
) -> OpResult<exec::Output> {
    let d = connect(ctx)?;
    let e = d
        .create_exec(
            name,
            ExecConfig {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(cmd),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| match e {
            bollard::errors::Error::DockerResponseServerError {
                status_code: 409, ..
            } => OpError::failed(format!("nginx 容器 {name} 未运行")),
            e => engine(e),
        })?;
    let collect = async {
        let mut out = exec::Output {
            code: -1,
            stdout: String::new(),
            stderr: String::new(),
        };
        if let StartExecResults::Attached { mut output, .. } = d
            .start_exec(&e.id, None::<StartExecOptions>)
            .await
            .map_err(engine)?
        {
            while let Some(item) = output.next().await {
                push_output(&mut out, item.map_err(engine)?);
            }
        }
        out.code = d
            .inspect_exec(&e.id)
            .await
            .map_err(engine)?
            .exit_code
            .unwrap_or(-1) as i32;
        Ok::<_, OpError>(out)
    };
    tokio::time::timeout(timeout, collect)
        .await
        .map_err(|_| OpError::failed(format!("在容器中执行超时（{}s）", timeout.as_secs())))?
}

fn push_output(out: &mut exec::Output, item: bollard::container::LogOutput) {
    use bollard::container::LogOutput as L;
    match item {
        L::StdErr { message } => out.stderr.push_str(&String::from_utf8_lossy(&message)),
        L::StdOut { message } | L::Console { message } => {
            out.stdout.push_str(&String::from_utf8_lossy(&message))
        }
        L::StdIn { .. } => {}
    }
}

pub async fn container_action(ctx: &Ctx, name: &str, a: Action, log: &Log) -> OpResult<()> {
    let d = connect(ctx)?;
    log.line(format!("容器 {name}"));
    let r = match a {
        Action::Start => d.start_container(name, None::<StartContainerOptions>).await,
        Action::Stop => {
            d.stop_container(name, Some(StopContainerOptionsBuilder::new().t(15).build()))
                .await
        }
        Action::Restart => {
            d.restart_container(
                name,
                Some(RestartContainerOptionsBuilder::new().t(15).build()),
            )
            .await
        }
    };
    match r {
        Ok(()) => Ok(()),
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 304, ..
        }) => {
            log.line("容器已处于目标状态");
            Ok(())
        }
        Err(e) => Err(engine(e)),
    }
}

// ---------------------------------------------------------------- container shape

/// Bind mounts of the nginx container, derived from the helper config.
pub fn binds(ctx: &Ctx) -> Vec<String> {
    let n = &ctx.cfg.nginx;
    let mut b = vec![
        format!("{}:{ETC}:ro", n.root.display()),
        format!("{}:/var/log/nginx", n.log_dir.display()),
    ];
    if Path::new("/etc/localtime").exists() {
        b.push("/etc/localtime:/etc/localtime:ro".into());
    }
    for p in n.site_roots.iter().chain(&n.cert_paths) {
        if Path::new(p).is_dir() {
            b.push(format!("{p}:{p}:ro"));
        }
    }
    b.extend(n.docker.binds.iter().cloned());
    b
}

fn body(
    image: &str,
    cmd: Option<Vec<String>>,
    binds: Vec<String>,
    role: &str,
    restart: bool,
) -> ContainerCreateBody {
    ContainerCreateBody {
        image: Some(image.to_string()),
        cmd,
        env: Some(vec!["NGINX_ENTRYPOINT_QUIET_LOGS=1".into()]),
        labels: Some(HashMap::from([(LABEL.to_string(), role.to_string())])),
        host_config: Some(HostConfig {
            binds: Some(binds),
            network_mode: Some("host".into()),
            restart_policy: restart.then_some(RestartPolicy {
                name: Some(RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Runs `cmd` in a throwaway container of `image` and returns its output.
async fn run_oneoff(
    d: &Docker,
    image: &str,
    cmd: &[&str],
    binds: Vec<String>,
) -> OpResult<exec::Output> {
    let cmd: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
    let id = d
        .create_container(None, body(image, Some(cmd), binds, "oneoff", false))
        .await
        .map_err(engine)?
        .id;
    let res = async {
        d.start_container(&id, None::<StartContainerOptions>)
            .await
            .map_err(engine)?;
        let mut wait = d.wait_container(&id, None::<WaitContainerOptions>);
        let code = match tokio::time::timeout(Duration::from_secs(120), wait.next()).await {
            Err(_) => return Err(OpError::failed("临时容器运行超时")),
            Ok(Some(Ok(r))) => r.status_code,
            Ok(Some(Err(bollard::errors::Error::DockerContainerWaitError { code, .. }))) => code,
            Ok(Some(Err(e))) => return Err(engine(e)),
            Ok(None) => -1,
        };
        let mut out = exec::Output {
            code: code as i32,
            stdout: String::new(),
            stderr: String::new(),
        };
        let mut logs = d.logs(
            &id,
            Some(LogsOptionsBuilder::new().stdout(true).stderr(true).build()),
        );
        while let Some(item) = logs.next().await {
            push_output(&mut out, item.map_err(engine)?);
        }
        Ok(out)
    }
    .await;
    let _ = d
        .remove_container(
            &id,
            Some(RemoveContainerOptionsBuilder::new().force(true).build()),
        )
        .await;
    res
}

fn log_output(log: &Log, out: &exec::Output) {
    for l in out.stdout.lines().chain(out.stderr.lines()) {
        if !l.trim().is_empty() {
            log.line(l.to_string());
        }
    }
}

/// `nginx -t` with `image` against the current config, without touching the running nginx.
async fn test_image(ctx: &Ctx, d: &Docker, image: &str, log: &Log) -> OpResult<exec::Output> {
    log.line(format!("$ nginx -t（{image}，临时容器）"));
    let out = run_oneoff(d, image, &["nginx", "-t"], binds(ctx)).await?;
    log_output(log, &out);
    Ok(out)
}

/// `nginx -t` for a stopped nginx container (with its image).
pub async fn test_stopped(ctx: &Ctx, name: &str, log: &Log) -> OpResult<exec::Output> {
    let image = inspect(ctx, name)
        .await
        .map(|i| i.image)
        .ok_or_else(|| OpError::failed(format!("找不到容器 {name}")))?;
    test_image(ctx, &connect(ctx)?, &image, log).await
}

// ---------------------------------------------------------------- state

#[derive(Default, serde::Serialize, Deserialize)]
struct State {
    previous_image: Option<String>,
}

fn load_state(ctx: &Ctx) -> State {
    std::fs::read(ctx.cfg.state_dir.join(STATE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_state(ctx: &Ctx, s: &State) -> OpResult<()> {
    std::fs::create_dir_all(&ctx.cfg.state_dir).map_err(|e| OpError::failed(e.to_string()))?;
    super::fsutil::atomic_write(
        &ctx.cfg.state_dir.join(STATE_FILE),
        &serde_json::to_vec(s).unwrap_or_default(),
    )
    .map_err(|e| OpError::failed(format!("保存 {STATE_FILE}：{e}")))
}

pub fn previous_image(ctx: &Ctx) -> Option<String> {
    load_state(ctx).previous_image
}

// ---------------------------------------------------------------- install

fn image_ref(ctx: &Ctx, version: &str) -> OpResult<String> {
    let ok = !version.is_empty()
        && version.len() <= 40
        && version.as_bytes()[0].is_ascii_digit()
        && version.split('-').next().is_some_and(|v| {
            let p: Vec<_> = v.split('.').collect();
            (2..=3).contains(&p.len())
                && p.iter()
                    .all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
        })
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !ok {
        return Err(OpError::invalid(format!(
            "无效的版本号 {version:?}（应为 1.27.3 或 1.27.3-alpine 这样的标签）"
        )));
    }
    Ok(format!("{}:{version}", ctx.cfg.nginx.docker.image))
}

fn root_is_etc(ctx: &Ctx) -> bool {
    ctx.cfg.nginx.root == Path::new(ETC)
}

/// Why `nginx.install` cannot run here (empty = it can).
pub async fn install_blockers(ctx: &Ctx) -> Vec<String> {
    let n = &ctx.cfg.nginx;
    let mut b = Vec::new();
    if !root_is_etc(ctx) {
        b.push(format!(
            "Docker 模式要求 nginx.root = {ETC}（当前为 {}）",
            n.root.display()
        ));
    }
    for dir in [n.root.as_path(), n.log_dir.as_path()] {
        if !writable(dir) {
            b.push(format!(
                "{} 不存在或不可写：请使用新版 tsmonitor-helper.service（启动前自动创建该目录），或执行 install -d {} 后 systemctl restart tsmonitor-helper",
                dir.display(),
                dir.display()
            ));
        }
    }
    if let Some(p) = rt::host_binary(ctx) {
        b.push(format!(
            "宿主机已安装 nginx（{}），请直接管理它，或先卸载系统包",
            p.display()
        ));
    } else if exec::unit_active("nginx.service").await {
        b.push("nginx.service 正在运行".into());
    }
    if !available(ctx).await {
        b.push(format!(
            "无法连接 Docker（{}）",
            ctx.cfg.docker.socket.display()
        ));
    } else if container_exists(ctx).await {
        b.push(format!("已存在名为 {} 的容器", n.docker.container));
    }
    for port in [80u16, 443] {
        if let Err(e) = std::net::TcpListener::bind(("0.0.0.0", port))
            && e.kind() == std::io::ErrorKind::AddrInUse
        {
            b.push(format!("端口 {port} 已被其他程序占用"));
        }
    }
    b
}

/// The directory exists and the helper can create files in it (systemd's ProtectSystem makes
/// paths that were missing at start read-only).
fn writable(dir: &Path) -> bool {
    let probe = dir.join(".tsmonitor-write-test");
    match std::fs::File::create(&probe) {
        Ok(_) => std::fs::remove_file(&probe).is_ok(),
        Err(_) => false,
    }
}

/// Copies the image's default config to the (empty) host root and switches it to the
/// sites-available / sites-enabled layout.
async fn seed(ctx: &Ctx, d: &Docker, image: &str, log: &Log) -> OpResult<()> {
    let root = &ctx.cfg.nginx.root;
    let io = |e: std::io::Error| OpError::failed(format!("初始化 {}：{e}", root.display()));
    log.line(format!(
        "{} 中没有 nginx.conf，从镜像复制默认配置",
        root.display()
    ));
    std::fs::create_dir_all(root).map_err(io)?;
    let out = run_oneoff(
        d,
        image,
        &["sh", "-c", "cp -a /etc/nginx/. /seed/"],
        vec![format!("{}:/seed", root.display())],
    )
    .await?;
    if !out.ok() {
        return Err(OpError::failed(format!(
            "复制默认配置失败：{}",
            out.message()
        )));
    }
    let conf = root.join("nginx.conf");
    let text = std::fs::read_to_string(&conf).map_err(io)?;
    let patched = add_sites_include(&text).ok_or_else(|| {
        OpError::failed("镜像自带的 nginx.conf 中没有 conf.d 的 include，无法启用站点目录")
    })?;
    std::fs::write(&conf, patched).map_err(io)?;
    for dir in ["sites-available", "sites-enabled"] {
        std::fs::create_dir_all(root.join(dir)).map_err(io)?;
    }
    let default = root.join("conf.d/default.conf");
    if default.is_file() {
        let avail = root.join("sites-available/default");
        std::fs::rename(&default, &avail).map_err(io)?;
        std::os::unix::fs::symlink(&avail, root.join("sites-enabled/default")).map_err(io)?;
    }
    log.line("已创建 sites-available / sites-enabled，默认站点为 default");
    Ok(())
}

/// Adds `include /etc/nginx/sites-enabled/*;` after the conf.d include of the http block.
fn add_sites_include(conf: &str) -> Option<String> {
    if conf.contains("sites-enabled/") {
        return Some(conf.to_string());
    }
    let mut out = String::with_capacity(conf.len() + 64);
    let mut done = false;
    for line in conf.split_inclusive('\n') {
        out.push_str(line);
        if !done && line.trim() == "include /etc/nginx/conf.d/*.conf;" {
            let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
            if !line.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("{indent}include /etc/nginx/sites-enabled/*;\n"));
            done = true;
        }
    }
    done.then_some(out)
}

fn ensure_dirs(ctx: &Ctx) -> OpResult<()> {
    let n = &ctx.cfg.nginx;
    for p in std::iter::once(n.log_dir.as_path()).chain(n.site_roots.iter().map(Path::new)) {
        std::fs::create_dir_all(p)
            .map_err(|e| OpError::failed(format!("创建 {}：{e}", p.display())))?;
    }
    for b in &n.docker.binds {
        if let Ok((h, _, _)) = parse_bind(b)
            && !Path::new(h).exists()
        {
            return Err(OpError::invalid(format!(
                "nginx.docker.binds 中的 {h} 不存在"
            )));
        }
    }
    Ok(())
}

async fn create_and_start(ctx: &Ctx, d: &Docker, image: &str, log: &Log) -> OpResult<()> {
    let name = &ctx.cfg.nginx.docker.container;
    log.line(format!(
        "创建容器 {name}（{image}，host 网络，unless-stopped）"
    ));
    d.create_container(
        Some(CreateContainerOptionsBuilder::new().name(name).build()),
        body(image, None, binds(ctx), "server", true),
    )
    .await
    .map_err(engine)?;
    d.start_container(name, None::<StartContainerOptions>)
        .await
        .map_err(engine)?;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    if !running(ctx, name).await {
        let mut out = exec::Output {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let mut logs = d.logs(
            name,
            Some(
                LogsOptionsBuilder::new()
                    .stdout(true)
                    .stderr(true)
                    .tail("20")
                    .build(),
            ),
        );
        while let Some(Ok(item)) = logs.next().await {
            push_output(&mut out, item);
        }
        log_output(log, &out);
        return Err(OpError::failed(format!("容器 {name} 启动后退出")));
    }
    Ok(())
}

async fn remove(d: &Docker, name: &str) {
    let _ = d
        .remove_container(
            name,
            Some(RemoveContainerOptionsBuilder::new().force(true).build()),
        )
        .await;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallArgs {
    version: String,
}

pub async fn install(ctx: &Ctx, a: InstallArgs, call: &Call<'_>) -> OpResult<Value> {
    super::nginx::allow(ctx, NginxOp::Install)?;
    let image = image_ref(ctx, &a.version)?;
    let blockers = install_blockers(ctx).await;
    if !blockers.is_empty() {
        return Err(OpError::invalid(format!(
            "无法安装：{}",
            blockers.join("；")
        )));
    }
    let name = ctx.cfg.nginx.docker.container.clone();
    let log = call.log;
    log.line(format!("用 Docker 安装 nginx：镜像 {image}，容器 {name}"));
    for b in binds(ctx) {
        log.line(format!("  挂载 {b}"));
    }
    if call.dry_run {
        log.line("（演练模式：未实际执行）");
        return Ok(json!({ "dry_run": true, "image": image }));
    }
    let d = connect(ctx)?;
    super::docker::pull(&d, &image, call).await?;
    if !ctx.cfg.nginx.root.join("nginx.conf").is_file() {
        seed(ctx, &d, &image, log).await?;
    }
    ensure_dirs(ctx)?;
    let t = test_image(ctx, &d, &image, log).await?;
    if !t.ok() {
        return Err(OpError::failed(format!(
            "现有配置未通过 {image} 的 nginx -t，未创建容器：\n{}",
            t.message()
        )));
    }
    if let Err(e) = create_and_start(ctx, &d, &image, log).await {
        remove(&d, &name).await;
        return Err(e);
    }
    rt::forget_version(ctx);
    if let Err(e) = super::nginx::probe(ctx, log).await {
        log.line("探测失败，删除新容器");
        remove(&d, &name).await;
        return Err(e);
    }
    save_state(ctx, &State::default())?;
    log.line("安装完成");
    Ok(json!({ "container": name, "image": image }))
}

// ---------------------------------------------------------------- upgrade / rollback

pub async fn upgrade(ctx: &Ctx, name: &str, version: &str, call: &Call<'_>) -> OpResult<Value> {
    let image = image_ref(ctx, version)?;
    switch(ctx, name, &image, call).await
}

pub async fn rollback(ctx: &Ctx, call: &Call<'_>) -> OpResult<Value> {
    super::nginx::allow(ctx, NginxOp::Upgrade)?;
    let rt::Runtime::Docker(name) = rt::detect(ctx).await else {
        return Err(OpError::invalid(
            "只有 Docker 方式运行的 nginx 可以回退版本",
        ));
    };
    let prev = previous_image(ctx).ok_or_else(|| OpError::invalid("没有可回退的上一个版本"))?;
    crate::ops::validate::image_ref(&prev)?;
    switch(ctx, &name, &prev, call).await
}

/// Replaces the container with one running `image`: pull, `nginx -t` with the new image,
/// stop the old container (kept under another name), start the new one and probe. Any
/// failure removes the new container and starts the old one again.
async fn switch(ctx: &Ctx, name: &str, image: &str, call: &Call<'_>) -> OpResult<Value> {
    let log = call.log;
    if !root_is_etc(ctx) {
        return Err(OpError::invalid(format!(
            "Docker 模式要求 nginx.root = {ETC}"
        )));
    }
    let old = inspect(ctx, name)
        .await
        .ok_or_else(|| OpError::failed(format!("找不到容器 {name}")))?;
    if old.image == image {
        return Err(OpError::invalid(format!("当前已是 {image}")));
    }
    log.line(format!("切换 nginx：{} → {image}", old.image));
    if call.dry_run {
        log.line("（演练模式）将拉取镜像、用新镜像执行 nginx -t、替换容器并探测，失败自动恢复");
        return Ok(json!({ "dry_run": true, "from": old.image, "to": image }));
    }
    let d = connect(ctx)?;
    super::docker::pull(&d, image, call).await?;
    ensure_dirs(ctx)?;
    let t = test_image(ctx, &d, image, log).await?;
    if !t.ok() {
        return Err(OpError::failed(format!(
            "当前配置未通过 {image} 的 nginx -t，未切换：\n{}",
            t.message()
        )));
    }
    let parked = format!("{name}-previous");
    remove(&d, &parked).await;
    d.rename_container(
        name,
        RenameContainerOptionsBuilder::new().name(&parked).build(),
    )
    .await
    .map_err(engine)?;
    log.line(format!("停止旧容器（暂存为 {parked}）"));
    if let Err(e) = d
        .stop_container(
            &parked,
            Some(StopContainerOptionsBuilder::new().t(15).build()),
        )
        .await
    {
        let _ = d
            .rename_container(
                &parked,
                RenameContainerOptionsBuilder::new().name(name).build(),
            )
            .await;
        return Err(engine(e));
    }
    let started = create_and_start(ctx, &d, image, log).await;
    rt::forget_version(ctx);
    let failed = match started {
        Err(e) => Some(e),
        Ok(()) => super::nginx::probe(ctx, log).await.err(),
    };
    if let Some(e) = failed {
        log.line(format!("切换失败，恢复 {}", old.image));
        remove(&d, name).await;
        let restore = async {
            d.rename_container(
                &parked,
                RenameContainerOptionsBuilder::new().name(name).build(),
            )
            .await
            .map_err(engine)?;
            d.start_container(name, None::<StartContainerOptions>)
                .await
                .map_err(engine)
        };
        if let Err(r) = restore.await {
            return Err(OpError::failed(format!(
                "{}；恢复旧容器也失败了：{}（旧容器名 {parked}）",
                e.message, r.message
            )));
        }
        rt::forget_version(ctx);
        return Err(OpError::failed(format!(
            "{}；已恢复 {}",
            e.message, old.image
        )));
    }
    remove(&d, &parked).await;
    save_state(
        ctx,
        &State {
            previous_image: Some(old.image.clone()),
        },
    )?;
    log.line(format!("完成，可回退到 {}", old.image));
    Ok(json!({ "from": old.image, "to": image }))
}

// ---------------------------------------------------------------- versions

/// Docker Hub repository path of the configured image, if it is on Docker Hub.
fn hub_repo(image: &str) -> Option<String> {
    let i = image
        .strip_prefix("docker.io/")
        .or_else(|| image.strip_prefix("index.docker.io/"))
        .unwrap_or(image);
    let parts: Vec<&str> = i.split('/').collect();
    match parts.as_slice() {
        [name] => Some(format!("library/{name}")),
        [org, _] if !org.contains(['.', ':']) && *org != "localhost" => Some(i.to_string()),
        _ => None,
    }
}

/// Plain `x.y.z` tags, newest first, with the nginx channel (even minor = stable).
fn version_list(tags: &[String]) -> Vec<Value> {
    let mut v: Vec<(u32, u32, u32)> = tags
        .iter()
        .filter_map(|t| {
            let p: Vec<_> = t.split('.').map(|x| x.parse::<u32>().ok()).collect();
            match p.as_slice() {
                [Some(a), Some(b), Some(c)]
                    if t.bytes().all(|x| x.is_ascii_digit() || x == b'.') =>
                {
                    Some((*a, *b, *c))
                }
                _ => None,
            }
        })
        .collect();
    v.sort_unstable_by(|a, b| b.cmp(a));
    v.dedup();
    // newest 20 per channel, so frequent mainline releases do not crowd out stable
    let mut count = [0usize; 2];
    v.into_iter()
        .filter_map(|(a, b, c)| {
            let stable = b % 2 == 0;
            let n = &mut count[stable as usize];
            *n += 1;
            (*n <= 20).then(|| {
                json!({
                    "version": format!("{a}.{b}.{c}"),
                    "channel": if stable { "stable" } else { "mainline" },
                    "latest": *n == 1,
                })
            })
        })
        .collect()
}

pub async fn versions(ctx: &Ctx) -> OpResult<Value> {
    let image = &ctx.cfg.nginx.docker.image;
    let repo = hub_repo(image).ok_or_else(|| {
        OpError::failed(format!(
            "{image} 不在 Docker Hub 上，无法列出版本，请手动输入版本号"
        ))
    })?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("tsmonitor-helper")
        .build()
        .map_err(|e| OpError::failed(e.to_string()))?;
    #[derive(Deserialize)]
    struct Page {
        next: Option<String>,
        results: Vec<Tag>,
    }
    #[derive(Deserialize)]
    struct Tag {
        name: String,
    }
    let mut url = Some(format!(
        "https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100&ordering=last_updated"
    ));
    let mut tags = Vec::new();
    for _ in 0..3 {
        let Some(u) = url.take() else { break };
        if !u.starts_with("https://hub.docker.com/") {
            break;
        }
        let p: Page = client
            .get(&u)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| OpError::failed(format!("查询 Docker Hub 失败：{e}")))?
            .json()
            .await
            .map_err(|e| OpError::failed(format!("解析 Docker Hub 响应失败：{e}")))?;
        tags.extend(p.results.into_iter().map(|t| t.name));
        url = p.next;
    }
    Ok(json!({ "image": image, "versions": version_list(&tags) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sites_include_goes_after_conf_d() {
        let conf = "http {\n    include       /etc/nginx/mime.types;\n    include /etc/nginx/conf.d/*.conf;\n}\n";
        let out = add_sites_include(conf).unwrap();
        assert!(out.contains(
            "    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;\n}"
        ));
        assert_eq!(add_sites_include(&out).unwrap(), out);
        assert!(add_sites_include("http {}\n").is_none());
    }

    #[test]
    fn versions_are_sorted_with_channels() {
        let tags: Vec<String> = [
            "1.27.3",
            "stable",
            "1.26.2",
            "1.27.3-alpine",
            "1.27.10",
            "1.26.2",
            "mainline",
            "1.25.5",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let v = version_list(&tags);
        let names: Vec<_> = v.iter().map(|x| x["version"].as_str().unwrap()).collect();
        assert_eq!(names, ["1.27.10", "1.27.3", "1.26.2", "1.25.5"]);
        assert_eq!(v[0]["channel"], "mainline");
        assert_eq!(v[0]["latest"], true);
        assert_eq!(v[1]["latest"], false);
        assert_eq!(v[2]["channel"], "stable");
        assert_eq!(v[2]["latest"], true);
    }

    #[test]
    fn hub_repos() {
        assert_eq!(hub_repo("nginx").as_deref(), Some("library/nginx"));
        assert_eq!(
            hub_repo("docker.io/library/nginx").as_deref(),
            Some("library/nginx")
        );
        assert_eq!(hub_repo("bitnami/nginx").as_deref(), Some("bitnami/nginx"));
        assert_eq!(hub_repo("ghcr.io/org/nginx"), None);
        assert_eq!(hub_repo("registry:5000/nginx"), None);
    }

    #[test]
    fn version_tags_are_validated() {
        let mut cfg: crate::helper::HelperConfig = toml::from_str("allowed_uids = []").unwrap();
        cfg.state_dir = std::env::temp_dir();
        let ctx = Ctx::new(cfg).unwrap();
        assert_eq!(image_ref(&ctx, "1.27.3").unwrap(), "nginx:1.27.3");
        assert_eq!(
            image_ref(&ctx, "1.27.3-alpine").unwrap(),
            "nginx:1.27.3-alpine"
        );
        assert_eq!(image_ref(&ctx, "1.27").unwrap(), "nginx:1.27");
        for bad in ["latest", "", "1.27.3;rm", "../x", "1..2", "1.27.3/../x"] {
            assert!(image_ref(&ctx, bad).is_err(), "{bad}");
        }
    }
}
