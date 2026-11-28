//! nginx domain: test, reload, enable/disable sites, edit config files, service control,
//! Docker install and version upgrades (see `nginx_runtime`, `nginx_docker`, `nginx_pkg`). Every change is
//! followed by `nginx -t`; a failed test, reload or probe restores the previous files.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use super::config::NginxOp;
use super::fsutil::{self, Backup};
use super::{Call, Ctx, Domain, Log, exec, not_enabled, op_not_allowed};
use crate::ops::nginx as inv;
use crate::ops::proto::{ErrorCode, OpError, OpResult};
use crate::ops::validate;

pub(super) fn allow(ctx: &Ctx, op: NginxOp) -> OpResult<()> {
    if ctx.cfg.nginx.allow.contains(&op) {
        Ok(())
    } else {
        Err(op_not_allowed("nginx", &op))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathArgs {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteArgs {
    name: String,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    path: String,
    content: String,
    /// sha256 of the file as it was read; empty or missing = the file must not exist yet.
    #[serde(default)]
    base_sha256: Option<String>,
}

pub async fn handle(ctx: &Ctx, op: &str, call: Call<'_>) -> OpResult<Value> {
    let n = &ctx.cfg.nginx;
    if !n.enabled {
        return Err(not_enabled("nginx"));
    }
    let root = n.root.clone();
    match op {
        "sites" => {
            let mut sites = inv::sites(&root);
            super::nginx_site::annotate(ctx, &root, &mut sites);
            Ok(json!({ "layout": inv::layout(&root), "sites": sites }))
        }
        "site_get" => super::nginx_site::get(ctx, &root, call.args()?),
        "site_save" => {
            let a = call.args()?;
            let _g = ctx.lock(Domain::Nginx).await?;
            super::nginx_site::save(ctx, &root, a, &call).await
        }
        "site_delete" => {
            let a = call.args()?;
            let _g = ctx.lock(Domain::Nginx).await?;
            super::nginx_site::delete(ctx, &root, a, &call).await
        }
        // takes the nginx lock itself, only for installing the result
        "cert_issue" => super::nginx_cert::issue(ctx, &root, call.args()?, &call).await,
        "cert_upload" => {
            let a = call.args()?;
            let _g = ctx.lock(Domain::Nginx).await?;
            super::nginx_cert::upload(ctx, &root, a, &call).await
        }
        "files" => Ok(json!(inv::files(&root, &n.edit_dirs))),
        "file" => {
            let a: PathArgs = call.args()?;
            Ok(json!(inv::read_file(&root, &a.path, &n.edit_dirs)?))
        }
        "test" => {
            allow(ctx, NginxOp::Test)?;
            let out = test(ctx, call.log).await?;
            Ok(json!({ "ok": out.ok(), "output": out.message() }))
        }
        "reload" => {
            allow(ctx, NginxOp::Reload)?;
            let _g = ctx.lock(Domain::Nginx).await?;
            if call.dry_run {
                call.log
                    .line("（演练模式）将执行 nginx -t，通过后重新加载 nginx");
                return Ok(json!({ "dry_run": true }));
            }
            let t = test(ctx, call.log).await?;
            if !t.ok() {
                return Err(OpError::failed(format!(
                    "配置检查未通过，未重新加载：\n{}",
                    t.message()
                )));
            }
            reload(ctx, call.log).await?;
            probe(ctx, call.log).await?;
            Ok(json!({ "reloaded": true }))
        }
        "site" => {
            let a: SiteArgs = call.args()?;
            allow(ctx, NginxOp::Site)?;
            let name = validate::file_name(&a.name)?.to_string();
            let _g = ctx.lock(Domain::Nginx).await?;
            site(ctx, &root, &name, a.enabled, &call).await
        }
        "status" => Ok(super::nginx_runtime::status(ctx).await),
        "versions" => super::nginx_docker::versions(ctx).await,
        "log_tail" => super::nginx_runtime::log_tail(ctx, call.args()?),
        "service" => {
            let a = call.args()?;
            let _g = ctx.lock(Domain::Nginx).await?;
            super::nginx_runtime::service(ctx, a, &call).await
        }
        "install" => {
            let a = call.args()?;
            let _g = ctx.lock(Domain::Nginx).await?;
            super::nginx_docker::install(ctx, a, &call).await
        }
        "upgrade" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                #[serde(default)]
                version: Option<String>,
            }
            let a: A = call.args()?;
            let _g = ctx.lock(Domain::Nginx).await?;
            super::nginx_pkg::upgrade_any(ctx, a.version, &call).await
        }
        "rollback" => {
            let _: serde::de::IgnoredAny = call.args()?;
            let _g = ctx.lock(Domain::Nginx).await?;
            super::nginx_docker::rollback(ctx, &call).await
        }
        "write" => {
            let a: WriteArgs = call.args()?;
            allow(ctx, NginxOp::Edit)?;
            let _g = ctx.lock(Domain::Nginx).await?;
            write(ctx, &root, a, &call).await
        }
        _ => Err(OpError::invalid(format!("unknown call nginx.{op}"))),
    }
}

async fn test(ctx: &Ctx, log: &Log) -> OpResult<exec::Output> {
    super::nginx_runtime::test(ctx, log).await
}

async fn reload(ctx: &Ctx, log: &Log) -> OpResult<()> {
    super::nginx_runtime::reload(ctx, log).await
}

/// GETs the configured probe URL after a reload; 5xx or no answer counts as broken.
pub(super) async fn probe(ctx: &Ctx, log: &Log) -> OpResult<()> {
    let Some(url) = &ctx.cfg.nginx.probe_url else {
        return Ok(());
    };
    // give the new workers a moment to take over
    tokio::time::sleep(Duration::from_millis(800)).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| OpError::failed(e.to_string()))?;
    match client.get(url).send().await {
        Ok(r) if !r.status().is_server_error() => {
            log.line(format!("探测 {url} → {}", r.status()));
            Ok(())
        }
        Ok(r) => Err(OpError::failed(format!("探测 {url} 返回 {}", r.status()))),
        Err(e) => Err(OpError::failed(format!("探测 {url} 失败：{e}"))),
    }
}

/// Runs after files changed: test, reload, probe. On any failure restores `backups` and, if the
/// reload already happened, reloads the restored config.
pub(super) async fn apply_or_rollback(ctx: &Ctx, backups: &[Backup], log: &Log) -> OpResult<()> {
    let rollback = |why: String, reloaded: bool| async move {
        log.line(format!("回滚：{why}"));
        for b in backups.iter().rev() {
            if let Err(e) = fsutil::restore(b) {
                log.line(format!("恢复 {} 失败：{e:#}", b.path.display()));
            }
        }
        if reloaded {
            let _ = reload(ctx, log).await;
        }
        OpError::failed(format!("{why}；已恢复原配置"))
    };
    let t = test(ctx, log).await?;
    if !t.ok() {
        return Err(rollback(format!("nginx -t 未通过：\n{}", t.message()), false).await);
    }
    if let Err(e) = reload(ctx, log).await {
        return Err(rollback(e.message, true).await);
    }
    if let Err(e) = probe(ctx, log).await {
        return Err(rollback(e.message, true).await);
    }
    Ok(())
}

async fn site(
    ctx: &Ctx,
    root: &Path,
    name: &str,
    enable: bool,
    call: &Call<'_>,
) -> OpResult<Value> {
    let state = &ctx.cfg.state_dir;
    let action = if enable { "启用" } else { "停用" };
    match inv::layout(root) {
        inv::Layout::SitesEnabled => {
            let target = fsutil::confined(root, &["sites-available".into(), name.into()])?;
            if !target.is_file() {
                return Err(OpError::invalid(format!("sites-available/{name} 不存在")));
            }
            let link = root.join("sites-enabled").join(name);
            let exists = std::fs::symlink_metadata(&link).ok();
            if let Some(m) = &exists
                && !m.file_type().is_symlink()
            {
                return Err(OpError::invalid(format!(
                    "sites-enabled/{name} 是普通文件而不是符号链接，请手动处理"
                )));
            }
            if enable == exists.is_some() {
                call.log.line(format!("站点 {name} 已经是{action}状态"));
                return Ok(json!({ "changed": false }));
            }
            call.log.line(format!("{action}站点 {name}"));
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true }));
            }
            let undo = |create: bool| -> std::io::Result<()> {
                if create {
                    std::os::unix::fs::symlink(&target, &link)
                } else {
                    std::fs::remove_file(&link)
                }
            };
            undo(enable).map_err(|e| OpError::failed(format!("{action}失败：{e}")))?;
            let t = test(ctx, call.log).await?;
            let failed = if !t.ok() {
                Some(format!("nginx -t 未通过：\n{}", t.message()))
            } else if let Err(e) = reload(ctx, call.log).await {
                Some(e.message)
            } else {
                probe(ctx, call.log).await.err().map(|e| e.message)
            };
            if let Some(why) = failed {
                let _ = undo(!enable);
                let _ = reload(ctx, call.log).await;
                return Err(OpError::failed(format!("{why}；已恢复原状态")));
            }
            Ok(json!({ "changed": true }))
        }
        inv::Layout::ConfD => {
            let on = fsutil::confined(root, &["conf.d".into(), format!("{name}.conf")])?;
            let off = fsutil::confined(root, &["conf.d".into(), format!("{name}.conf.disabled")])?;
            let (from, to): (PathBuf, PathBuf) = if enable { (off, on) } else { (on, off) };
            if !from.is_file() {
                if to.is_file() {
                    call.log.line(format!("站点 {name} 已经是{action}状态"));
                    return Ok(json!({ "changed": false }));
                }
                return Err(OpError::invalid(format!("找不到站点 {name}")));
            }
            if to.exists() {
                return Err(OpError::invalid(format!(
                    "{} 已存在，请手动处理",
                    to.display()
                )));
            }
            call.log.line(format!(
                "{action}站点 {name}：{} → {}",
                from.display(),
                to.display()
            ));
            if call.dry_run {
                call.log.line("（演练模式：未实际执行）");
                return Ok(json!({ "dry_run": true }));
            }
            let b_from = fsutil::backup(state, "nginx", &from)?;
            let b_to = Backup::absent(&to);
            std::fs::rename(&from, &to)
                .map_err(|e| OpError::failed(format!("{action}失败：{e}")))?;
            apply_or_rollback(ctx, &[b_from, b_to], call.log).await?;
            Ok(json!({ "changed": true }))
        }
    }
}

async fn write(ctx: &Ctx, root: &Path, a: WriteArgs, call: &Call<'_>) -> OpResult<Value> {
    let n = &ctx.cfg.nginx;
    let parts = inv::check_path(&a.path, &n.edit_dirs, true)?;
    if a.content.len() > inv::MAX_FILE {
        return Err(OpError::invalid("文件超过 512 KiB"));
    }
    inv::check_directives(&a.content)?;
    let path = fsutil::confined(root, &parts)?;
    let current = match std::fs::read(&path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(OpError::failed(format!("读取 {}：{e}", a.path))),
    };
    let base = a.base_sha256.filter(|s| !s.is_empty());
    match (&current, &base) {
        (Some(cur), Some(b)) if &fsutil::sha256_hex(cur) == b => {}
        (None, None) => {}
        (Some(_), None) => {
            return Err(OpError::new(
                ErrorCode::Conflict,
                format!("{} 已存在，请先读取后再修改", a.path),
            ));
        }
        (None, Some(_)) => {
            return Err(OpError::new(
                ErrorCode::Conflict,
                format!("{} 已被删除", a.path),
            ));
        }
        _ => {
            return Err(OpError::new(
                ErrorCode::Conflict,
                format!("{} 在你读取之后被修改过，请重新加载后再保存", a.path),
            ));
        }
    }
    let old = current
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default()
        .into_owned();
    let diff = inv::unified_diff(&a.path, &old, &a.content);
    if diff.trim().is_empty() {
        call.log.line("内容没有变化");
        return Ok(json!({ "changed": false, "diff": "" }));
    }
    if call.dry_run {
        call.log
            .line(format!("（演练模式）将写入 {}，未实际执行", a.path));
        return Ok(json!({ "dry_run": true, "diff": diff }));
    }
    call.log.line(format!("写入 {}", a.path));
    let b = fsutil::backup(&ctx.cfg.state_dir, "nginx", &path)?;
    fsutil::atomic_write(&path, a.content.as_bytes())?;
    apply_or_rollback(ctx, &[b], call.log).await?;
    let sha = fsutil::sha256_hex(a.content.as_bytes());
    Ok(json!({ "changed": true, "diff": diff, "sha256": sha }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::helper::Ctx;
    use crate::ops::proto::Actor;

    /// A fake `nginx` binary: `-t` fails when an active conf (`*.conf`, or anything linked
    /// from `sites-enabled`) contains BROKEN.
    fn fake_nginx(dir: &Path, root: &Path) -> String {
        let bin = dir.join("fake-nginx");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"-t\" ]; then\n  if grep -rq --include=*.conf BROKEN {r} || cat {r}/sites-enabled/* 2>/dev/null | grep -q BROKEN ; then echo 'nginx: [emerg] unexpected' >&2; exit 1; fi\n  echo 'test is successful' >&2; exit 0\nfi\nexit 0\n",
                r = root.display()
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        bin.to_string_lossy().into_owned()
    }

    fn ctx(dir: &Path, root: &Path) -> std::sync::Arc<Ctx> {
        ctx_with(dir, root, |n| n.allow.push(NginxOp::Edit))
    }

    /// Context with the fake nginx and test / reload / site / edit allowed; `f` adjusts the
    /// nginx domain further.
    pub(crate) fn ctx_with(
        dir: &Path,
        root: &Path,
        f: impl FnOnce(&mut crate::helper::config::NginxDomain),
    ) -> std::sync::Arc<Ctx> {
        let mut cfg: crate::helper::HelperConfig = toml::from_str("allowed_uids = []").unwrap();
        cfg.state_dir = dir.join("state");
        cfg.nginx.enabled = true;
        cfg.nginx.root = root.to_path_buf();
        cfg.nginx.allow = vec![NginxOp::Site, NginxOp::Reload, NginxOp::Test];
        cfg.nginx.binary = fake_nginx(dir, root);
        cfg.nginx.runtime = crate::helper::config::NginxRuntime::Host;
        f(&mut cfg.nginx);
        Ctx::new(cfg).unwrap()
    }

    pub(crate) async fn call(ctx: &Ctx, op: &str, args: Value, dry_run: bool) -> OpResult<Value> {
        let log = Log::sink(op);
        let actor = Actor::default();
        handle(
            ctx,
            op,
            Call {
                args: &args,
                dry_run,
                actor: &actor,
                log: &log,
            },
        )
        .await
    }

    #[tokio::test]
    async fn broken_config_is_rejected_and_restored_byte_identical() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("nginx");
        std::fs::create_dir_all(root.join("conf.d")).unwrap();
        let original = "server { listen 80; server_name a; }\n";
        std::fs::write(root.join("conf.d/a.conf"), original).unwrap();
        let ctx = ctx(d.path(), &root);
        let sha = fsutil::sha256_hex(original.as_bytes());

        // dry run returns a diff and changes nothing
        let v = call(&ctx, "write", json!({ "path": "conf.d/a.conf", "content": "server { listen 81; }\n", "base_sha256": sha }), true).await.unwrap();
        assert!(
            v["diff"]
                .as_str()
                .unwrap()
                .contains("+server { listen 81; }")
        );
        assert_eq!(
            std::fs::read_to_string(root.join("conf.d/a.conf")).unwrap(),
            original
        );

        // stale base hash
        let e = call(
            &ctx,
            "write",
            json!({ "path": "conf.d/a.conf", "content": "x", "base_sha256": "00" }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);

        // broken config: nginx -t fails, file restored exactly
        let e = call(
            &ctx,
            "write",
            json!({ "path": "conf.d/a.conf", "content": "BROKEN\n", "base_sha256": sha }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Failed, "{e}");
        assert_eq!(
            std::fs::read(root.join("conf.d/a.conf")).unwrap(),
            original.as_bytes()
        );

        // forbidden directive never reaches the disk
        let e = call(
            &ctx,
            "write",
            json!({ "path": "conf.d/a.conf", "content": "load_module x.so;", "base_sha256": sha }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Invalid);

        // a good change goes through
        let v = call(&ctx, "write", json!({ "path": "conf.d/a.conf", "content": "server { listen 82; }\n", "base_sha256": sha }), false).await.unwrap();
        assert_eq!(v["changed"], true);

        // new file must not exist yet; a broken new file is removed again
        let e = call(
            &ctx,
            "write",
            json!({ "path": "conf.d/new.conf", "content": "BROKEN" }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Failed);
        assert!(!root.join("conf.d/new.conf").exists());
    }

    #[tokio::test]
    async fn site_toggle_conf_d_rolls_back() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("nginx");
        std::fs::create_dir_all(root.join("conf.d")).unwrap();
        std::fs::write(root.join("conf.d/app.conf"), "server { listen 80; }").unwrap();
        std::fs::write(root.join("conf.d/bad.conf.disabled"), "server { BROKEN }").unwrap();
        let ctx = ctx(d.path(), &root);
        call(
            &ctx,
            "site",
            json!({ "name": "app", "enabled": false }),
            false,
        )
        .await
        .unwrap();
        assert!(root.join("conf.d/app.conf.disabled").exists());
        let e = call(
            &ctx,
            "site",
            json!({ "name": "bad", "enabled": true }),
            false,
        )
        .await;
        assert!(e.is_err());
        assert!(root.join("conf.d/bad.conf.disabled").exists());
        assert!(!root.join("conf.d/bad.conf").exists());
    }
}
