//! nginx installed from the distribution (apt): installed and candidate version, and upgrade
//! to the candidate. A package upgrade cannot be rolled back automatically; the config is
//! tested before and after, and the result is probed.

use std::time::Duration;

use serde_json::{Value, json};

use super::config::NginxOp;
use super::nginx_runtime::{self as rt, Runtime};
use super::{Call, Ctx, exec};
use crate::ops::proto::{OpError, OpResult};

const PACKAGE: &str = "nginx";

/// `{ manager: "apt", installed, candidate }`, or None without dpkg / when nginx is not a package.
pub async fn info() -> Option<Value> {
    crate::sandbox::which("dpkg-query")?;
    let installed = installed_version().await?;
    let candidate = candidate_version().await;
    Some(json!({ "manager": "apt", "installed": installed, "candidate": candidate }))
}

async fn installed_version() -> Option<String> {
    let o = exec::run(
        &exec::argv(&["dpkg-query", "-W", "-f=${Status}|${Version}", PACKAGE]),
        Duration::from_secs(10),
    )
    .await
    .ok()?;
    let (status, version) = o.stdout.trim().split_once('|')?;
    (o.ok() && status.ends_with(" installed") && !version.is_empty()).then(|| version.to_string())
}

async fn candidate_version() -> Option<String> {
    crate::sandbox::which("apt-cache")?;
    let o = exec::run(
        &exec::argv(&["apt-cache", "policy", PACKAGE]),
        Duration::from_secs(20),
    )
    .await
    .ok()?;
    parse_candidate(&o.stdout)
}

fn parse_candidate(policy: &str) -> Option<String> {
    policy
        .lines()
        .find_map(|l| l.trim().strip_prefix("Candidate:"))
        .map(str::trim)
        .filter(|v| !v.is_empty() && *v != "(none)")
        .map(str::to_string)
}

/// `apt-get install --only-upgrade nginx`, keeping the local config files.
pub async fn upgrade(ctx: &Ctx, call: &Call<'_>) -> OpResult<Value> {
    if crate::sandbox::which("apt-get").is_none() {
        return Err(OpError::invalid(
            "此主机没有 apt，无法通过面板升级系统包版 nginx",
        ));
    }
    let from = installed_version()
        .await
        .ok_or_else(|| OpError::invalid("nginx 不是通过 apt 安装的系统包，无法通过面板升级"))?;
    let to = candidate_version().await;
    if to.as_deref() == Some(from.as_str()) || to.is_none() {
        return Err(OpError::invalid(format!(
            "已是 apt 源中的最新版本 {from}（可先在“系统更新”中刷新软件源）"
        )));
    }
    let to = to.unwrap_or_default();
    call.log.line(format!("升级系统包 nginx：{from} → {to}"));
    let t = rt::test(ctx, call.log).await?;
    if !t.ok() {
        return Err(OpError::failed(format!(
            "当前配置未通过 nginx -t，先修复再升级：\n{}",
            t.message()
        )));
    }
    if call.dry_run {
        call.log.line("（演练模式：未实际执行）");
        return Ok(json!({ "dry_run": true, "from": from, "to": to }));
    }
    let out = exec::run_logged(
        call.log,
        &exec::argv(&[
            "apt-get",
            "install",
            "-y",
            "--only-upgrade",
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
            PACKAGE,
        ]),
        Duration::from_secs(900),
    )
    .await?;
    rt::forget_version(ctx);
    if !out.ok() {
        return Err(OpError::failed(format!(
            "apt-get 失败（系统包升级无法自动回退，请登录服务器检查）：{}",
            out.message()
        )));
    }
    let now = installed_version().await.unwrap_or_default();
    call.log.line(format!("已安装 {now}"));
    let t = rt::test(ctx, call.log).await?;
    if !t.ok() {
        return Err(OpError::failed(format!(
            "升级后配置检查未通过（系统包升级无法自动回退）：\n{}",
            t.message()
        )));
    }
    if exec::unit_loaded("nginx.service").await && !exec::unit_active("nginx.service").await {
        return Err(OpError::failed(
            "升级后 nginx.service 未在运行，请检查 journalctl -u nginx",
        ));
    }
    super::nginx::probe(ctx, call.log).await?;
    Ok(json!({ "from": from, "to": now }))
}

/// `nginx.upgrade`: apt on the host, image swap for the container.
pub async fn upgrade_any(ctx: &Ctx, version: Option<String>, call: &Call<'_>) -> OpResult<Value> {
    super::nginx::allow(ctx, NginxOp::Upgrade)?;
    match rt::detect(ctx).await {
        Runtime::Host(_) => {
            if version.is_some() {
                return Err(OpError::invalid(
                    "系统包版 nginx 只能升级到 apt 源中的候选版本，不能指定版本",
                ));
            }
            upgrade(ctx, call).await
        }
        Runtime::Docker(c) => {
            let v = version.ok_or_else(|| OpError::invalid("请指定要切换到的版本"))?;
            super::nginx_docker::upgrade(ctx, &c, &v, call).await
        }
        Runtime::None => Err(OpError::invalid("未安装 nginx")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_from_apt_cache_policy() {
        let p = "nginx:\n  Installed: 1.22.1-9\n  Candidate: 1.22.1-9+deb12u1\n  Version table:\n";
        assert_eq!(parse_candidate(p).as_deref(), Some("1.22.1-9+deb12u1"));
        assert_eq!(
            parse_candidate("nginx:\n  Installed: (none)\n  Candidate: (none)\n"),
            None
        );
    }
}
