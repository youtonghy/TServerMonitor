//! Managed sites: create, change and delete nginx sites from a [`SiteSpec`]. The spec is kept
//! next to the helper's backups (`<state_dir>/nginx-sites/<name>.json`, root only); the
//! rendered config carries a marker line so anyone can tell it is generated.
//!
//! A save writes the spec, the config and (for a new Debian-layout site) the `sites-enabled`
//! link, then runs the usual test / reload / probe; any failure restores all of them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::config::NginxOp;
use super::fsutil;
use super::nginx::{allow, apply_or_rollback};
use super::{Call, Ctx, exec};
use crate::ops::nginx as inv;
use crate::ops::nginx_site::{self as spec_mod, CertInfo, RenderEnv, SiteSpec, SslMode};
use crate::ops::proto::{ErrorCode, OpError, OpResult};

const SITES_DIR: &str = "nginx-sites";

/// What the helper remembers about a managed site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteState {
    pub spec: SiteSpec,
    #[serde(default)]
    pub cert: CertInfo,
}

pub fn state_path(ctx: &Ctx, name: &str) -> PathBuf {
    ctx.cfg
        .state_dir
        .join(SITES_DIR)
        .join(format!("{name}.json"))
}

pub fn load_state(ctx: &Ctx, name: &str) -> OpResult<Option<SiteState>> {
    match std::fs::read(state_path(ctx, name)) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| OpError::failed(format!("站点记录 {name} 已损坏：{e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(OpError::failed(format!("读取站点记录 {name}：{e}"))),
    }
}

pub fn write_state(ctx: &Ctx, st: &SiteState) -> OpResult<()> {
    let path = state_path(ctx, &st.spec.name);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| OpError::failed(format!("{e}")))?;
    }
    let data = serde_json::to_vec_pretty(st).map_err(|e| OpError::failed(e.to_string()))?;
    fsutil::atomic_write_mode(&path, &data, 0o600)?;
    Ok(())
}

/// Names of all sites with a state record.
pub fn managed_names(ctx: &Ctx) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(ctx.cfg.state_dir.join(SITES_DIR))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".json"))
                .filter(|n| spec_mod::site_name(n).is_ok())
                .map(str::to_string)
        })
        .collect();
    out.sort();
    out
}

/// Where a site's config lives on this host.
pub struct Location {
    pub conf: PathBuf,
    /// Relative to the nginx root, as shown in the file list.
    pub rel: String,
    /// `sites-enabled/<name>` in the Debian layout.
    pub link: Option<PathBuf>,
    pub exists: bool,
    pub enabled: bool,
}

pub fn locate(root: &Path, name: &str) -> OpResult<Location> {
    match inv::layout(root) {
        inv::Layout::SitesEnabled => {
            let rel = format!("sites-available/{name}");
            let conf = fsutil::confined(root, &["sites-available".into(), name.into()])?;
            let link = root.join("sites-enabled").join(name);
            let linked = std::fs::symlink_metadata(&link).is_ok();
            let exists = conf.is_file();
            Ok(Location {
                conf,
                rel,
                link: Some(link),
                exists,
                enabled: !exists || linked,
            })
        }
        inv::Layout::ConfD => {
            let on = fsutil::confined(root, &["conf.d".into(), format!("{name}.conf")])?;
            let off = fsutil::confined(root, &["conf.d".into(), format!("{name}.conf.disabled")])?;
            let (conf, rel, exists, enabled) = if on.is_file() {
                (on, format!("conf.d/{name}.conf"), true, true)
            } else if off.is_file() {
                (off, format!("conf.d/{name}.conf.disabled"), true, false)
            } else {
                (on, format!("conf.d/{name}.conf"), false, true)
            };
            Ok(Location {
                conf,
                rel,
                link: None,
                exists,
                enabled,
            })
        }
    }
}

pub fn own_dir(root: &Path) -> PathBuf {
    root.join(spec_mod::OWN_DIR)
}

pub fn challenge_dir(root: &Path) -> PathBuf {
    own_dir(root).join("acme-challenge")
}

/// (fullchain, key) of the certificate the site would use, when both files exist.
pub fn cert_files(root: &Path, spec: &SiteSpec) -> Option<(PathBuf, PathBuf)> {
    let (c, k) = match spec.ssl.mode {
        SslMode::None => return None,
        SslMode::Path => (
            PathBuf::from(&spec.ssl.cert_path),
            PathBuf::from(&spec.ssl.key_path),
        ),
        SslMode::Acme | SslMode::Upload => {
            let (c, k) = spec.managed_cert_rel();
            (root.join(c), root.join(k))
        }
    };
    (c.is_file() && k.is_file()).then_some((c, k))
}

/// nginx version as (major, minor, patch), detected once.
async fn nginx_version(ctx: &Ctx) -> Option<(u32, u32, u32)> {
    *ctx.nginx_version
        .get_or_init(|| async {
            let out = exec::run(
                &exec::argv(&[&ctx.cfg.nginx.binary, "-v"]),
                Duration::from_secs(10),
            )
            .await
            .ok()?;
            parse_version(&format!("{}{}", out.stderr, out.stdout))
        })
        .await
}

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let v = s.split("nginx/").nth(1)?;
    let mut it = v
        .split(|c: char| !c.is_ascii_digit())
        .map(|x| x.parse::<u32>());
    Some((it.next()?.ok()?, it.next()?.ok()?, it.next()?.ok()?))
}

pub async fn render_env(ctx: &Ctx, root: &Path, spec: &SiteSpec) -> RenderEnv {
    let cert = cert_files(root, spec).map(|(c, k)| {
        (
            c.to_string_lossy().into_owned(),
            k.to_string_lossy().into_owned(),
        )
    });
    RenderEnv {
        cert,
        challenge_dir: format!("{}/", challenge_dir(root).display()),
        http2_directive: nginx_version(ctx).await.is_some_and(|v| v >= (1, 25, 1)),
    }
}

/// Host-dependent checks on a normalised spec.
fn check_host(ctx: &Ctx, root: &Path, spec: &SiteSpec) -> OpResult<()> {
    let n = &ctx.cfg.nginx;
    if spec.kind == spec_mod::SiteKind::Static
        && !n.site_roots.iter().any(|r| {
            spec_mod::under(&spec.static_site.root, r)
                && spec.static_site.root != r.trim_end_matches('/')
        })
    {
        return Err(OpError::invalid(format!(
            "网站根目录必须位于这些目录之下：{}（helper.toml 的 [nginx] site_roots）",
            n.site_roots.join(", ")
        )));
    }
    if !spec.extra.is_empty() && !n.allow.contains(&NginxOp::Edit) {
        return Err(OpError::not_allowed(
            "自定义配置可以写入任意指令，需要在 helper.toml 的 [nginx] allow 中同时开启 edit",
        ));
    }
    if spec.ssl.mode != SslMode::None {
        allow(ctx, NginxOp::Cert)?;
    }
    match spec.ssl.mode {
        SslMode::Acme if !n.acme.enabled => {
            return Err(OpError::not_allowed(
                "此主机未开启自动申请证书（helper.toml 的 [nginx.acme] enabled）",
            ));
        }
        SslMode::Path => {
            for (what, p) in [("证书", &spec.ssl.cert_path), ("私钥", &spec.ssl.key_path)] {
                let real = std::fs::canonicalize(p)
                    .map_err(|e| OpError::invalid(format!("{what}文件 {p} 不可用：{e}")))?;
                let real = real.to_string_lossy();
                if !n.cert_paths.iter().any(|r| spec_mod::under(&real, r)) {
                    return Err(OpError::invalid(format!(
                        "{what}文件必须位于这些目录之下：{}（helper.toml 的 [nginx] cert_paths）",
                        n.cert_paths.join(", ")
                    )));
                }
                if !Path::new(p).is_file() {
                    return Err(OpError::invalid(format!("{what}文件 {p} 不是普通文件")));
                }
            }
        }
        _ => {}
    }
    // nginx only warns about a duplicate server_name and then serves one of them at random
    for s in inv::sites(root) {
        if s.name == spec.name {
            continue;
        }
        if let Some(d) = spec
            .domains
            .iter()
            .find(|d| s.server_names.iter().any(|x| x.eq_ignore_ascii_case(d)))
        {
            return Err(OpError::invalid(format!(
                "域名 {d} 已绑定在站点 {}（{}）上",
                s.name, s.file
            )));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    name: String,
}

pub fn get(ctx: &Ctx, root: &Path, a: GetArgs) -> OpResult<Value> {
    let name = spec_mod::site_name(&a.name)?;
    let st = load_state(ctx, name)?
        .ok_or_else(|| OpError::invalid(format!("站点 {name} 不是由面板管理的站点")))?;
    let loc = locate(root, name)?;
    let (sha256, drifted) = if loc.exists {
        let text = std::fs::read(&loc.conf).map_err(|e| OpError::failed(e.to_string()))?;
        let marker = spec_mod::parse_marker(&String::from_utf8_lossy(&text));
        (
            Some(fsutil::sha256_hex(&text)),
            marker.is_none_or(|m| m.drifted || m.name != name),
        )
    } else {
        (None, false)
    };
    Ok(json!({
        "spec": st.spec,
        "cert": super::nginx_cert::cert_info(root, &st),
        "file": loc.rel,
        "exists": loc.exists,
        "enabled": loc.enabled,
        "sha256": sha256,
        "drifted": drifted,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveArgs {
    spec: SiteSpec,
    /// sha256 of the config as returned by `nginx.site_get`; absent = create a new site.
    #[serde(default)]
    base_sha256: Option<String>,
    /// Replace a managed config that was edited by hand.
    #[serde(default)]
    overwrite: bool,
}

pub async fn save(ctx: &Ctx, root: &Path, a: SaveArgs, call: &Call<'_>) -> OpResult<Value> {
    allow(ctx, NginxOp::Manage)?;
    let mut spec = a.spec;
    spec.normalize()?;
    check_host(ctx, root, &spec)?;
    let name = spec.name.clone();
    let loc = locate(root, &name)?;
    let prev = load_state(ctx, &name)?;
    let current = if loc.exists {
        Some(
            std::fs::read(&loc.conf)
                .map_err(|e| OpError::failed(format!("读取 {}：{e}", loc.rel)))?,
        )
    } else {
        None
    };
    let base = a.base_sha256.filter(|s| !s.is_empty());
    let mut drift_note = None;
    match (&current, &base) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(OpError::new(
                ErrorCode::Conflict,
                format!("{} 已被删除", loc.rel),
            ));
        }
        (Some(_), None) => {
            return Err(OpError::new(
                ErrorCode::Conflict,
                format!("已存在同名站点 {}，请换一个站点名", loc.rel),
            ));
        }
        (Some(cur), Some(b)) => {
            if &fsutil::sha256_hex(cur) != b {
                return Err(OpError::new(
                    ErrorCode::Conflict,
                    format!("{} 在你打开之后被修改过，请重新打开后再保存", loc.rel),
                ));
            }
            let text = String::from_utf8_lossy(cur);
            let marker = spec_mod::parse_marker(&text).filter(|m| m.name == name);
            if prev.is_none() && marker.is_none() {
                return Err(OpError::new(
                    ErrorCode::Conflict,
                    format!("{} 是手动维护的站点，不能用表单覆盖", loc.rel),
                ));
            }
            if marker.is_none_or(|m| m.drifted) {
                if !a.overwrite {
                    return Err(OpError::new(
                        ErrorCode::Conflict,
                        format!(
                            "{} 生成后被手动修改过，保存会覆盖这些修改；请查看差异后确认覆盖",
                            loc.rel
                        ),
                    ));
                }
                drift_note = Some(format!("覆盖 {} 中的手动修改", loc.rel));
            }
        }
    }
    let env = render_env(ctx, root, &spec).await;
    let content = spec_mod::render(&spec, &env);
    let old = current
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default()
        .into_owned();
    let diff = inv::unified_diff(&loc.rel, &old, &content);
    let spec_same = prev.as_ref().is_some_and(|p| p.spec == spec);
    if diff.trim().is_empty() && spec_same {
        call.log.line("内容没有变化");
        return Ok(json!({ "changed": false, "diff": "", "file": loc.rel }));
    }
    if spec.ssl.mode != SslMode::None && env.cert.is_none() {
        call.log
            .line("证书尚未就绪：先以 HTTP 提供服务，证书就绪后自动切换到 HTTPS");
    }
    if call.dry_run {
        call.log.line(format!(
            "（演练模式）将{} {}，未实际执行",
            if loc.exists { "更新" } else { "创建" },
            loc.rel
        ));
        return Ok(json!({ "dry_run": true, "diff": diff, "file": loc.rel }));
    }
    if let Some(n) = drift_note {
        call.log.line(n);
    }
    if spec.kind == spec_mod::SiteKind::Static {
        ensure_root(&spec.static_site.root, call)?;
    }
    if !loc.enabled {
        call.log
            .line("站点当前处于停用状态，配置会在启用时生效（届时再次检查）");
    }

    let state = &ctx.cfg.state_dir;
    let mut backups = vec![
        fsutil::backup(state, "nginx", &state_path(ctx, &name))?,
        fsutil::backup(state, "nginx", &loc.conf)?,
    ];
    let st = SiteState {
        cert: CertInfo {
            mode: spec.ssl.mode,
            ..prev.map(|p| p.cert).unwrap_or_default()
        },
        spec,
    };
    write_state(ctx, &st)?;
    call.log.line(format!(
        "{} {}",
        if loc.exists { "更新" } else { "创建" },
        loc.rel
    ));
    fsutil::atomic_write(&loc.conf, content.as_bytes())?;
    if let Some(link) = &loc.link
        && !loc.exists
    {
        backups.push(fsutil::backup_link(link)?);
        call.log.line(format!("启用：sites-enabled/{name}"));
        std::os::unix::fs::symlink(&loc.conf, link)
            .map_err(|e| OpError::failed(format!("创建 sites-enabled/{name}：{e}")))?;
    }
    apply_or_rollback(ctx, &backups, call.log).await?;
    Ok(json!({
        "changed": true,
        "diff": diff,
        "file": loc.rel,
        "sha256": fsutil::sha256_hex(content.as_bytes()),
    }))
}

/// Creates an empty document root (0755) so a new static site answers right away.
fn ensure_root(dir: &str, call: &Call<'_>) -> OpResult<()> {
    let p = Path::new(dir);
    if p.is_dir() {
        return Ok(());
    }
    call.log.line(format!("创建网站目录 {dir}"));
    let res = (|| {
        std::fs::create_dir_all(p)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
    })();
    res.map_err(|e| {
        if e.raw_os_error() == Some(libc::EROFS) {
            OpError::failed(format!(
                "无法创建 {dir}：文件系统只读。请更新 tsmonitor-helper.service（ReadWritePaths 需包含 -/var/www）后重启助手，或先手动创建该目录"
            ))
        } else {
            OpError::failed(format!("创建 {dir}：{e}"))
        }
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteArgs {
    name: String,
    /// Also remove uploaded / issued certificates.
    #[serde(default)]
    purge_certs: bool,
}

pub async fn delete(ctx: &Ctx, root: &Path, a: DeleteArgs, call: &Call<'_>) -> OpResult<Value> {
    allow(ctx, NginxOp::Manage)?;
    let name = spec_mod::site_name(&a.name)?.to_string();
    let loc = locate(root, &name)?;
    let st = load_state(ctx, &name)?;
    let marked = loc.exists
        && std::fs::read_to_string(&loc.conf)
            .ok()
            .and_then(|t| spec_mod::parse_marker(&t))
            .is_some_and(|m| m.name == name);
    if st.is_none() && !marked {
        return Err(OpError::invalid(format!(
            "站点 {name} 不是由面板管理的站点，请在配置文件中手动删除"
        )));
    }
    let link = loc
        .link
        .as_ref()
        .filter(|l| std::fs::symlink_metadata(l).is_ok_and(|m| m.file_type().is_symlink()));
    call.log.line(format!("删除站点 {name}：{}", loc.rel));
    if call.dry_run {
        call.log.line("（演练模式：未实际执行）");
        return Ok(json!({ "dry_run": true }));
    }
    let state = &ctx.cfg.state_dir;
    let mut backups = vec![fsutil::backup(state, "nginx", &state_path(ctx, &name))?];
    if loc.exists {
        backups.push(fsutil::backup(state, "nginx", &loc.conf)?);
    }
    if let Some(l) = link {
        backups.push(fsutil::backup_link(l)?);
    }
    let rm = |p: &Path| match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(OpError::failed(format!("删除 {}：{e}", p.display()))),
    };
    for b in backups.iter().rev() {
        rm(&b.path)?;
    }
    apply_or_rollback(ctx, &backups, call.log).await?;
    if a.purge_certs {
        let dir = own_dir(root).join("certs").join(&name);
        if dir.is_dir() {
            call.log.line(format!("删除证书目录 {}", dir.display()));
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                call.log.line(format!("删除证书目录失败：{e}"));
            }
        }
    }
    Ok(json!({ "changed": true }))
}

/// Adds certificate state to the managed entries of a site list.
pub fn annotate(ctx: &Ctx, root: &Path, sites: &mut [inv::Site]) {
    for s in sites.iter_mut().filter(|s| s.managed) {
        if let Ok(Some(st)) = load_state(ctx, &s.name) {
            s.cert = Some(super::nginx_cert::cert_info(root, &st));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::nginx::tests::{call, ctx_with};

    fn proxy_spec(name: &str, domain: &str) -> Value {
        json!({
            "name": name,
            "domains": [domain],
            "kind": "proxy",
            "proxy": { "upstream": "http://127.0.0.1:3000" },
        })
    }

    #[test]
    fn version_parsing() {
        assert_eq!(
            parse_version("nginx version: nginx/1.24.0\n"),
            Some((1, 24, 0))
        );
        assert_eq!(
            parse_version("nginx version: nginx/1.27.3 (Ubuntu)"),
            Some((1, 27, 3))
        );
        assert_eq!(parse_version(""), None);
    }

    #[tokio::test]
    async fn create_update_toggle_delete_debian_layout() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("nginx");
        std::fs::create_dir_all(root.join("sites-available")).unwrap();
        std::fs::create_dir_all(root.join("sites-enabled")).unwrap();
        std::fs::write(
            root.join("sites-available/manual"),
            "server { listen 80; server_name taken.example.com; }",
        )
        .unwrap();
        let ctx = ctx_with(d.path(), &root, |n| {
            n.allow.push(NginxOp::Manage);
        });

        // permission and validation
        let e = call(
            &ctx,
            "site_save",
            json!({ "spec": proxy_spec("app", "taken.example.com") }),
            false,
        )
        .await
        .unwrap_err();
        assert!(e.message.contains("已绑定在站点 manual"), "{e}");
        let e = call(
            &ctx,
            "site_save",
            json!({ "spec": proxy_spec("manual", "x.example.com") }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);

        // dry run: diff, nothing written
        let v = call(
            &ctx,
            "site_save",
            json!({ "spec": proxy_spec("app", "app.example.com") }),
            true,
        )
        .await
        .unwrap();
        assert!(
            v["diff"]
                .as_str()
                .unwrap()
                .contains("+    server_name app.example.com;")
        );
        assert!(!root.join("sites-available/app").exists());

        // create: config, link and state
        call(
            &ctx,
            "site_save",
            json!({ "spec": proxy_spec("app", "app.example.com") }),
            false,
        )
        .await
        .unwrap();
        assert!(std::fs::read_link(root.join("sites-enabled/app")).is_ok());
        let sites = call(&ctx, "sites", json!({}), false).await.unwrap();
        let app = sites["sites"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "app")
            .unwrap()
            .clone();
        assert_eq!(app["managed"], true);
        assert_eq!(app["kind"], "proxy");
        assert_eq!(app["drifted"], false);

        // update needs the current hash; a broken render rolls back conf + state
        let got = call(&ctx, "site_get", json!({ "name": "app" }), false)
            .await
            .unwrap();
        let sha = got["sha256"].as_str().unwrap().to_string();
        let before = std::fs::read(root.join("sites-available/app")).unwrap();
        let state_before = std::fs::read(state_path(&ctx, "app")).unwrap();
        let mut broken = proxy_spec("app", "app.example.com");
        broken["proxy"]["upstream"] = json!("http://BROKEN:1");
        let e = call(
            &ctx,
            "site_save",
            json!({ "spec": broken, "base_sha256": sha }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Failed, "{e}");
        assert_eq!(
            std::fs::read(root.join("sites-available/app")).unwrap(),
            before
        );
        assert_eq!(
            std::fs::read(state_path(&ctx, "app")).unwrap(),
            state_before
        );

        let mut two = proxy_spec("app", "app.example.com");
        two["domains"] = json!(["app.example.com", "www.app.example.com"]);
        let e = call(
            &ctx,
            "site_save",
            json!({ "spec": two, "base_sha256": "00" }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::Conflict);
        call(
            &ctx,
            "site_save",
            json!({ "spec": two, "base_sha256": sha }),
            false,
        )
        .await
        .unwrap();
        let got = call(&ctx, "site_get", json!({ "name": "app" }), false)
            .await
            .unwrap();
        assert_eq!(got["spec"]["domains"][1], "www.app.example.com");

        // a hand edit must be confirmed before it is overwritten
        let path = root.join("sites-available/app");
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("3000", "3001");
        std::fs::write(&path, &edited).unwrap();
        let sha = fsutil::sha256_hex(edited.as_bytes());
        let e = call(
            &ctx,
            "site_save",
            json!({ "spec": two, "base_sha256": sha }),
            false,
        )
        .await
        .unwrap_err();
        assert!(e.message.contains("手动修改"), "{e}");
        call(
            &ctx,
            "site_save",
            json!({ "spec": two, "base_sha256": sha, "overwrite": true }),
            false,
        )
        .await
        .unwrap();

        // toggling with the existing call keeps it managed; saving keeps it disabled
        call(
            &ctx,
            "site",
            json!({ "name": "app", "enabled": false }),
            false,
        )
        .await
        .unwrap();
        let got = call(&ctx, "site_get", json!({ "name": "app" }), false)
            .await
            .unwrap();
        assert_eq!(got["enabled"], false);
        let mut three = two.clone();
        three["proxy"]["websocket"] = json!(true);
        call(
            &ctx,
            "site_save",
            json!({ "spec": three, "base_sha256": got["sha256"] }),
            false,
        )
        .await
        .unwrap();
        assert!(std::fs::symlink_metadata(root.join("sites-enabled/app")).is_err());

        // manual sites cannot be deleted here; managed ones can
        assert!(
            call(&ctx, "site_delete", json!({ "name": "manual" }), false)
                .await
                .is_err()
        );
        call(
            &ctx,
            "site",
            json!({ "name": "app", "enabled": true }),
            false,
        )
        .await
        .unwrap();
        call(&ctx, "site_delete", json!({ "name": "app" }), false)
            .await
            .unwrap();
        assert!(!root.join("sites-available/app").exists());
        assert!(std::fs::symlink_metadata(root.join("sites-enabled/app")).is_err());
        assert!(load_state(&ctx, "app").unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_rolls_back_link_and_files() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("nginx");
        std::fs::create_dir_all(root.join("sites-available")).unwrap();
        std::fs::create_dir_all(root.join("sites-enabled")).unwrap();
        let ctx = ctx_with(d.path(), &root, |n| n.allow.push(NginxOp::Manage));
        call(
            &ctx,
            "site_save",
            json!({ "spec": proxy_spec("app", "app.example.com") }),
            false,
        )
        .await
        .unwrap();
        // something else on the host is broken: deleting must not leave a half-removed site
        std::fs::write(root.join("sites-available/other"), "BROKEN").unwrap();
        std::os::unix::fs::symlink(
            root.join("sites-available/other"),
            root.join("sites-enabled/other"),
        )
        .unwrap();
        let e = call(&ctx, "site_delete", json!({ "name": "app" }), false).await;
        assert!(e.is_err());
        assert!(root.join("sites-available/app").is_file());
        assert!(std::fs::read_link(root.join("sites-enabled/app")).is_ok());
        assert!(load_state(&ctx, "app").unwrap().is_some());
    }

    #[tokio::test]
    async fn static_site_conf_d_layout_and_root_allowlist() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("nginx");
        std::fs::create_dir_all(root.join("conf.d")).unwrap();
        let www = d.path().join("www");
        let www_s = www.to_string_lossy().into_owned();
        let ctx = ctx_with(d.path(), &root, |n| {
            n.allow.push(NginxOp::Manage);
            n.site_roots = vec![www_s.clone()];
        });
        let spec = |r: &str| {
            json!({
                "name": "docs",
                "domains": ["docs.example.com"],
                "kind": "static",
                "static": { "root": r },
            })
        };
        let e = call(&ctx, "site_save", json!({ "spec": spec("/etc") }), false)
            .await
            .unwrap_err();
        assert!(e.message.contains("site_roots"), "{e}");
        // the allowed root itself is not a site directory
        assert!(
            call(&ctx, "site_save", json!({ "spec": spec(&www_s) }), false)
                .await
                .is_err()
        );
        let docs = format!("{www_s}/docs");
        call(&ctx, "site_save", json!({ "spec": spec(&docs) }), false)
            .await
            .unwrap();
        assert!(www.join("docs").is_dir());
        let conf = std::fs::read_to_string(root.join("conf.d/docs.conf")).unwrap();
        assert!(conf.contains(&format!("root {docs};")));
        // custom directives need `edit` as well
        let mut s = spec(&docs);
        s["extra"] = json!("add_header X-A b;");
        let sha = fsutil::sha256_hex(conf.as_bytes());
        let e = call(
            &ctx,
            "site_save",
            json!({ "spec": s, "base_sha256": sha }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotAllowed);
        // TLS needs the cert permission
        let mut s = spec(&docs);
        s["ssl"] = json!({ "mode": "upload" });
        let e = call(
            &ctx,
            "site_save",
            json!({ "spec": s, "base_sha256": sha }),
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotAllowed);
    }
}
