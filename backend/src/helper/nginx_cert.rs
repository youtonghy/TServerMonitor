//! Certificates of managed sites: inspection, upload and (see [`super::acme`]) issuance.
//!
//! Uploaded and issued certificates live in `<nginx root>/tsmonitor/certs/<site>/`
//! (`fullchain.pem` 0644, `privkey.pem` 0600, directory 0700; nginx reads them as root).
//! Private keys never leave the helper: they are not returned, logged or stored in jobs.

use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};

use super::config::NginxOp;
use super::fsutil;
use super::nginx::{allow, apply_or_rollback};
use super::nginx_site::{self as site, SiteState};
use super::{Call, Ctx};
use crate::ops::nginx_site::{self as spec_mod, CertInfo, SslMode};
use crate::ops::proto::{OpError, OpResult};

const MAX_PEM: usize = 64 * 1024;

/// What a certificate chain says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub not_before: i64,
    pub not_after: i64,
    pub names: Vec<String>,
    pub issuer: String,
}

/// Parses the first (leaf) certificate of a PEM chain.
pub fn parse_chain(pem: &[u8]) -> OpResult<Parsed> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::pem::Pem;
    let mut leaf = None;
    for p in Pem::iter_from_buffer(pem) {
        let p = p.map_err(|e| OpError::invalid(format!("证书 PEM 格式错误：{e}")))?;
        if p.label != "CERTIFICATE" {
            return Err(OpError::invalid(format!(
                "证书文件中包含 {}，只能包含 CERTIFICATE",
                p.label
            )));
        }
        let x = p
            .parse_x509()
            .map_err(|e| OpError::invalid(format!("无法解析证书：{e}")))?;
        if leaf.is_none() {
            let mut names = Vec::new();
            if let Ok(Some(san)) = x.subject_alternative_name() {
                for n in &san.value.general_names {
                    if let GeneralName::DNSName(d) = n {
                        names.push(d.to_ascii_lowercase());
                    }
                }
            }
            if names.is_empty()
                && let Some(cn) = x.subject().iter_common_name().next()
                && let Ok(cn) = cn.as_str()
            {
                names.push(cn.to_ascii_lowercase());
            }
            let v = x.validity();
            leaf = Some(Parsed {
                not_before: v.not_before.timestamp() * 1000,
                not_after: v.not_after.timestamp() * 1000,
                names,
                issuer: x.issuer().to_string(),
            });
        }
    }
    leaf.ok_or_else(|| OpError::invalid("没有找到证书（应以 -----BEGIN CERTIFICATE----- 开头）"))
}

/// True when the certificate name `pattern` (possibly `*.example.com`) covers `host`.
pub fn covers(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(base) => host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == base),
        None => pattern == host,
    }
}

/// Current certificate state of a managed site, read from the files nginx uses.
pub fn cert_info(root: &Path, st: &SiteState) -> CertInfo {
    let mut info = CertInfo {
        mode: st.spec.ssl.mode,
        not_after: None,
        not_before: None,
        names: Vec::new(),
        issuer: None,
        ..st.cert.clone()
    };
    if let Some((chain, _)) = site::cert_files(root, &st.spec)
        && let Ok(data) = std::fs::read(&chain)
        && let Ok(p) = parse_chain(&data)
    {
        info.not_after = Some(p.not_after);
        info.not_before = Some(p.not_before);
        info.names = p.names;
        info.issuer = Some(p.issuer);
    }
    info
}

fn check_key(pem: &str) -> OpResult<()> {
    let t = pem.trim();
    let ok = t.len() <= MAX_PEM
        && t.starts_with("-----BEGIN ")
        && t.lines()
            .next()
            .is_some_and(|l| l.ends_with("PRIVATE KEY-----"))
        && t.ends_with("PRIVATE KEY-----")
        && !t.contains("ENCRYPTED");
    ok.then_some(()).ok_or_else(|| {
        OpError::invalid(
            "私钥必须是未加密的 PEM（-----BEGIN PRIVATE KEY----- 或 RSA / EC PRIVATE KEY）",
        )
    })
}

/// Writes a certificate pair for `name`, returning backups of the previous files.
pub fn install(
    ctx: &Ctx,
    root: &Path,
    spec: &spec_mod::SiteSpec,
    chain: &str,
    key: &str,
) -> OpResult<Vec<fsutil::Backup>> {
    let (c, k) = spec.managed_cert_rel();
    let (c, k) = (root.join(c), root.join(k));
    let dir = c.parent().expect("cert dir");
    let own = site::own_dir(root);
    for d in [own.as_path(), &own.join("certs"), dir] {
        if let Ok(m) = std::fs::symlink_metadata(d)
            && !m.is_dir()
        {
            return Err(OpError::failed(format!("{} 不是目录", d.display())));
        }
    }
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir)
            .map_err(|e| OpError::failed(format!("创建 {}：{e}", dir.display())))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| OpError::failed(e.to_string()))?;
    }
    let state = &ctx.cfg.state_dir;
    let backups = vec![
        fsutil::backup(state, "nginx-certs", &c)?,
        fsutil::backup(state, "nginx-certs", &k)?,
    ];
    let mut chain = chain.trim().to_string();
    chain.push('\n');
    let mut key = key.trim().to_string();
    key.push('\n');
    fsutil::atomic_write_mode(&k, key.as_bytes(), 0o600)?;
    fsutil::atomic_write_mode(&c, chain.as_bytes(), 0o644)?;
    Ok(backups)
}

/// Re-renders a managed site after its certificate changed and applies it; restores the
/// certificate, config and state on failure. The caller holds the nginx lock.
pub async fn apply_cert(
    ctx: &Ctx,
    root: &Path,
    mut st: SiteState,
    mut backups: Vec<fsutil::Backup>,
    call: &Call<'_>,
) -> OpResult<String> {
    let loc = site::locate(root, &st.spec.name)?;
    if !loc.exists {
        for b in backups.iter().rev() {
            let _ = fsutil::restore(b);
        }
        return Err(OpError::invalid(format!(
            "站点 {} 的配置文件不存在",
            st.spec.name
        )));
    }
    let env = site::render_env(ctx, root, &st.spec).await;
    let content = spec_mod::render(&st.spec, &env);
    let state = &ctx.cfg.state_dir;
    backups.push(fsutil::backup(
        state,
        "nginx",
        &site::state_path(ctx, &st.spec.name),
    )?);
    backups.push(fsutil::backup(state, "nginx", &loc.conf)?);
    st.cert.last_error = None;
    site::write_state(ctx, &st)?;
    fsutil::atomic_write(&loc.conf, content.as_bytes())?;
    call.log.line(format!("更新 {}（启用 HTTPS）", loc.rel));
    apply_or_rollback(ctx, &backups, call.log).await?;
    Ok(fsutil::sha256_hex(content.as_bytes()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadArgs {
    name: String,
    cert_pem: String,
    key_pem: String,
}

pub async fn upload(ctx: &Ctx, root: &Path, a: UploadArgs, call: &Call<'_>) -> OpResult<Value> {
    allow(ctx, NginxOp::Cert)?;
    let name = spec_mod::site_name(&a.name)?.to_string();
    let mut st = site::load_state(ctx, &name)?
        .ok_or_else(|| OpError::invalid(format!("站点 {name} 不是由面板管理的站点")))?;
    if a.cert_pem.len() > MAX_PEM {
        return Err(OpError::invalid("证书文件过大"));
    }
    let p = parse_chain(a.cert_pem.as_bytes())?;
    check_key(&a.key_pem)?;
    let now = chrono::Utc::now().timestamp_millis();
    if p.not_after <= now {
        return Err(OpError::invalid("证书已过期"));
    }
    let missing: Vec<&String> = st
        .spec
        .domains
        .iter()
        .filter(|d| !p.names.iter().any(|n| covers(n, d)))
        .collect();
    if !missing.is_empty() {
        call.log.line(format!(
            "注意：证书不包含这些域名，浏览器访问时会报错：{}",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    call.log.line(format!(
        "证书：{}，有效期至 {}，签发者 {}",
        p.names.join(", "),
        chrono::DateTime::from_timestamp_millis(p.not_after)
            .map(|t| t.format("%Y-%m-%d").to_string())
            .unwrap_or_default(),
        p.issuer
    ));
    if call.dry_run {
        call.log
            .line("（演练模式）将安装证书并启用 HTTPS，未实际执行");
        return Ok(json!({ "dry_run": true }));
    }
    st.spec.ssl.mode = SslMode::Upload;
    st.spec.ssl.cert_path.clear();
    st.spec.ssl.key_path.clear();
    st.cert.mode = SslMode::Upload;
    let backups = install(ctx, root, &st.spec, &a.cert_pem, &a.key_pem)?;
    let sha = apply_cert(ctx, root, st, backups, call).await?;
    Ok(json!({ "changed": true, "not_after": p.not_after, "sha256": sha }))
}

// ---------------------------------------------------------------- ACME issuance

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueArgs {
    name: String,
    /// Issue even when the current certificate is far from expiry.
    #[serde(default)]
    force: bool,
}

/// Removes the challenge files it published when dropped.
struct Published {
    dir: std::path::PathBuf,
    files: std::sync::Mutex<Vec<std::path::PathBuf>>,
}

impl Published {
    fn new(root: &Path) -> OpResult<Self> {
        use std::os::unix::fs::PermissionsExt;
        let own = site::own_dir(root);
        let dir = site::challenge_dir(root);
        std::fs::create_dir_all(&dir)
            .map_err(|e| OpError::failed(format!("创建 {}：{e}", dir.display())))?;
        // nginx workers (www-data / nginx) must be able to traverse into it
        for d in [&own, &dir] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| OpError::failed(e.to_string()))?;
        }
        Ok(Self {
            dir,
            files: Default::default(),
        })
    }

    fn put(&self, token: &str, content: &str) -> OpResult<()> {
        let ok = !token.is_empty()
            && token.len() <= 256
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(OpError::failed(format!("CA 返回了无效的 token：{token:?}")));
        }
        let p = self.dir.join(token);
        fsutil::atomic_write_mode(&p, content.as_bytes(), 0o644)?;
        self.files.lock().expect("poisoned").push(p);
        Ok(())
    }
}

impl Drop for Published {
    fn drop(&mut self) {
        for f in self.files.lock().expect("poisoned").drain(..) {
            let _ = std::fs::remove_file(f);
        }
    }
}

/// Fetches a probe file through nginx for every domain before asking the CA, so a site that
/// cannot answer challenges fails here instead of using up the CA's failed-validation limit.
async fn preflight(
    ctx: &Ctx,
    root: &Path,
    spec: &spec_mod::SiteSpec,
    call: &Call<'_>,
) -> OpResult<()> {
    let probe = Published::new(root)?;
    let token = format!("tsm-probe-{}", uuid::Uuid::new_v4().simple());
    let content = uuid::Uuid::new_v4().simple().to_string();
    probe.put(&token, &content)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| OpError::failed(e.to_string()))?;
    let base = ctx
        .cfg
        .nginx
        .acme
        .preflight_url
        .clone()
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", spec.listen.http));
    let url = format!("{base}/.well-known/acme-challenge/{token}");
    for d in &spec.domains {
        // `systemctl reload` returns before the new workers answer: allow a few seconds
        let mut ok = false;
        let mut last = String::new();
        for attempt in 0..6 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            match client.get(&url).header("Host", d).send().await {
                Ok(r) if r.status().is_success() => {
                    if r.text().await.is_ok_and(|t| t.trim() == content) {
                        ok = true;
                        break;
                    }
                    last = "返回的内容不是验证文件（请求被其他站点处理了）".into();
                }
                Ok(r) => last = format!("本机返回 {}", r.status()),
                Err(e) => last = e.to_string(),
            }
        }
        if !ok {
            call.log.line(format!("自检 {d}：{last}"));
            return Err(OpError::failed(format!(
                "自检失败：本机 nginx 无法为 {d} 提供验证文件。请确认站点已启用并已重新加载，且没有其他站点抢占该域名"
            )));
        }
    }
    call.log.line("自检通过：nginx 能正确提供验证文件");
    Ok(())
}

/// First site domain the installed certificate does not cover.
fn uncovered<'a>(info: &CertInfo, domains: &'a [String]) -> Option<&'a String> {
    domains
        .iter()
        .find(|d| !info.names.iter().any(|n| covers(n, d)))
}

fn days_left(not_after: i64, now: i64) -> i64 {
    (not_after - now).div_euclid(86_400_000)
}

/// Records the outcome of an attempt in the site's state (best effort).
async fn record(ctx: &Ctx, name: &str, error: Option<String>) {
    let _g = ctx.lock(super::Domain::Nginx).await;
    if let Ok(Some(mut st)) = site::load_state(ctx, name) {
        st.cert.last_attempt = Some(chrono::Utc::now().timestamp_millis());
        st.cert.last_error = error;
        let _ = site::write_state(ctx, &st);
    }
}

pub async fn issue(ctx: &Ctx, root: &Path, a: IssueArgs, call: &Call<'_>) -> OpResult<Value> {
    allow(ctx, NginxOp::Cert)?;
    let acme = &ctx.cfg.nginx.acme;
    if !acme.enabled {
        return Err(OpError::not_allowed(
            "此主机未开启自动申请证书（helper.toml 的 [nginx.acme] enabled）",
        ));
    }
    let name = spec_mod::site_name(&a.name)?.to_string();
    let st = site::load_state(ctx, &name)?
        .ok_or_else(|| OpError::invalid(format!("站点 {name} 不是由面板管理的站点")))?;
    if st.spec.ssl.mode != SslMode::Acme {
        return Err(OpError::invalid(
            "请先把站点的 SSL 方式设为“自动申请”并保存",
        ));
    }
    let loc = site::locate(root, &name)?;
    if !loc.exists || !loc.enabled {
        return Err(OpError::invalid(format!(
            "站点 {name} 未启用，CA 无法访问验证文件；请先启用站点"
        )));
    }
    let text = std::fs::read_to_string(&loc.conf).unwrap_or_default();
    if !text.contains("/.well-known/acme-challenge/") {
        return Err(OpError::invalid(
            "站点配置中缺少验证路径，请重新保存站点后再申请",
        ));
    }
    let now = chrono::Utc::now().timestamp_millis();
    let info = cert_info(root, &st);
    if let Some(na) = info.not_after
        && !a.force
        && days_left(na, now) > i64::from(acme.renew_days)
        && uncovered(&info, &st.spec.domains).is_none()
    {
        call.log.line(format!(
            "证书还有 {} 天到期，暂不需要续期",
            days_left(na, now)
        ));
        return Ok(json!({ "changed": false, "not_after": na }));
    }
    let domains = st.spec.domains.clone();
    call.log.line(format!(
        "为 {} 申请证书（{}）",
        domains.join(", "),
        acme.directory_url()
    ));
    if call.dry_run {
        call.log
            .line("（演练模式）将进行本机自检、向 CA 申请证书并启用 HTTPS，未实际执行");
        return Ok(json!({ "dry_run": true }));
    }
    {
        let mut busy = ctx.issuing.lock().expect("poisoned");
        if !busy.insert(name.clone()) {
            return Err(OpError::busy(format!("站点 {name} 正在申请证书")));
        }
    }
    struct Done<'a>(&'a Ctx, String);
    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.issuing.lock().expect("poisoned").remove(&self.1);
        }
    }
    let _done = Done(ctx, name.clone());

    // the order itself runs without the nginx lock: it can take minutes
    let res = async {
        preflight(ctx, root, &st.spec, call).await?;
        let published = Published::new(root)?;
        let publish = |c: &super::acme::Challenge| {
            call.log.line(format!("发布 {} 的验证文件", c.domain));
            published.put(&c.token, &c.key_auth)
        };
        let issued = ctx
            .acme
            .issue(super::acme::IssueRequest {
                domains: &domains,
                publish: &publish,
                log: call.log,
            })
            .await?;
        drop(published);
        let p = parse_chain(issued.chain_pem.as_bytes())?;
        check_key(&issued.key_pem)?;
        if let Some(d) = domains
            .iter()
            .find(|d| !p.names.iter().any(|n| covers(n, d)))
        {
            return Err(OpError::failed(format!("签发的证书不包含 {d}")));
        }
        Ok((issued, p))
    }
    .await;
    let (issued, parsed) = match res {
        Ok(v) => v,
        Err(e) => {
            record(ctx, &name, Some(e.message.clone())).await;
            return Err(e);
        }
    };

    let _g = ctx.lock(super::Domain::Nginx).await?;
    // the site may have changed while the order ran
    let mut st = site::load_state(ctx, &name)?
        .filter(|s| s.spec.ssl.mode == SslMode::Acme)
        .ok_or_else(|| {
            OpError::failed(format!("站点 {name} 在申请期间被修改或删除，证书未安装"))
        })?;
    st.cert.mode = SslMode::Acme;
    st.cert.last_attempt = Some(now);
    let backups = install(ctx, root, &st.spec, &issued.chain_pem, &issued.key_pem)?;
    call.log.line(format!(
        "证书已签发：{}，有效期至 {}",
        parsed.names.join(", "),
        chrono::DateTime::from_timestamp_millis(parsed.not_after)
            .map(|t| t.format("%Y-%m-%d").to_string())
            .unwrap_or_default()
    ));
    match apply_cert(ctx, root, st, backups, call).await {
        Ok(sha) => Ok(json!({ "changed": true, "not_after": parsed.not_after, "sha256": sha })),
        Err(e) => {
            drop(_g);
            record(ctx, &name, Some(e.message.clone())).await;
            Err(e)
        }
    }
}

/// Renews ACME certificates close to expiry: first ~5 minutes after start, then twice a day.
pub async fn renew_loop(ctx: std::sync::Arc<Ctx>) {
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    loop {
        renew_due(&ctx).await;
        tokio::time::sleep(std::time::Duration::from_secs(12 * 3600)).await;
    }
}

/// Failed attempts are retried after this long.
const RETRY_MS: i64 = 6 * 3600 * 1000;

pub async fn renew_due(ctx: &Ctx) -> Vec<String> {
    let root = ctx.cfg.nginx.root.clone();
    let now = chrono::Utc::now().timestamp_millis();
    let mut renewed = Vec::new();
    for name in site::managed_names(ctx) {
        let Ok(Some(st)) = site::load_state(ctx, &name) else {
            continue;
        };
        if st.spec.ssl.mode != SslMode::Acme {
            continue;
        }
        let info = cert_info(&root, &st);
        let Some(na) = info.not_after else { continue };
        // due when close to expiry, or when domains were added since it was issued
        if days_left(na, now) > i64::from(ctx.cfg.nginx.acme.renew_days)
            && uncovered(&info, &st.spec.domains).is_none()
        {
            continue;
        }
        if info.last_error.is_some() && info.last_attempt.is_some_and(|t| now - t < RETRY_MS) {
            continue;
        }
        if ctx.cfg.dry_run {
            tracing::info!(target: "helper::audit", "renewal of {name} skipped (dry run)");
            continue;
        }
        tracing::info!(target: "helper::audit", "via=system call=nginx.cert_issue site={name} (renewal)");
        let log = super::Log::sink("nginx.cert_renew");
        let actor = crate::ops::proto::Actor {
            via: "system".into(),
            ..Default::default()
        };
        let args = Value::Null;
        let call = Call {
            args: &args,
            dry_run: false,
            actor: &actor,
            log: &log,
        };
        match issue(
            ctx,
            &root,
            IssueArgs {
                name: name.clone(),
                force: false,
            },
            &call,
        )
        .await
        {
            Ok(_) => renewed.push(name),
            Err(e) => {
                tracing::warn!(target: "helper::audit", "renewal of {name} failed: {}", e.message)
            }
        }
    }
    renewed
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::helper::nginx::tests::{call, ctx_with};

    /// A self-signed certificate and its key for `names`.
    pub(crate) fn self_signed(names: &[&str]) -> (String, String) {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let c = rcgen::generate_simple_self_signed(names).unwrap();
        (c.cert.pem(), c.signing_key.serialize_pem())
    }

    /// Self-signed, expiring in `days`.
    fn expiring(names: &[&str], days: i64) -> (String, String) {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let mut p = rcgen::CertificateParams::new(names).unwrap();
        let t = chrono::Utc::now() + chrono::Duration::days(days);
        use chrono::Datelike;
        p.not_after = rcgen::date_time_ymd(t.year(), t.month() as u8, t.day() as u8);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// Serves `<dir>/<token>` like the rendered challenge location does.
    async fn challenge_server(dir: std::path::PathBuf) -> String {
        use axum::extract::Path as P;
        let app = axum::Router::new().route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(move |P(t): P<String>| {
                let dir = dir.clone();
                async move {
                    std::fs::read_to_string(dir.join(t))
                        .map_err(|_| axum::http::StatusCode::NOT_FOUND)
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn acme_ctx(
        d: &Path,
        root: &Path,
        preflight: Option<String>,
    ) -> (
        std::sync::Arc<Ctx>,
        std::sync::Arc<crate::helper::acme::tests::FakeIssuer>,
    ) {
        let base = ctx_with(d, root, |n| {
            n.allow.push(NginxOp::Manage);
            n.allow.push(NginxOp::Cert);
            n.acme.enabled = true;
            n.acme.preflight_url = preflight;
        });
        let fake = std::sync::Arc::new(crate::helper::acme::tests::FakeIssuer {
            challenge_dir: site::challenge_dir(root),
            fail: Default::default(),
            calls: Default::default(),
        });
        let ctx = Ctx::with_issuer((*base.cfg).clone(), fake.clone()).unwrap();
        (ctx, fake)
    }

    #[tokio::test]
    async fn acme_issue_preflight_failure_and_renewal() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("nginx");
        std::fs::create_dir_all(root.join("conf.d")).unwrap();
        let url = challenge_server(site::challenge_dir(&root)).await;
        let (ctx, fake) = acme_ctx(d.path(), &root, Some(url));
        let spec = json!({
            "name": "app",
            "domains": ["app.example.com", "www.app.example.com"],
            "proxy": { "upstream": "http://127.0.0.1:3000" },
            "ssl": { "mode": "acme" },
        });
        call(&ctx, "site_save", json!({ "spec": spec }), false)
            .await
            .unwrap();
        let conf = root.join("conf.d/app.conf");
        let text = std::fs::read_to_string(&conf).unwrap();
        assert!(text.contains("acme-challenge") && !text.contains("443"));

        // dry run asks nobody
        call(&ctx, "cert_issue", json!({ "name": "app" }), true)
            .await
            .unwrap();
        assert_eq!(*fake.calls.lock().unwrap(), 0);

        // a CA failure is recorded and nothing changes
        *fake.fail.lock().unwrap() = true;
        assert!(
            call(&ctx, "cert_issue", json!({ "name": "app" }), false)
                .await
                .is_err()
        );
        let sites = call(&ctx, "sites", json!({}), false).await.unwrap();
        assert!(
            sites["sites"][0]["cert"]["last_error"]
                .as_str()
                .unwrap()
                .contains("验证未通过")
        );
        assert_eq!(std::fs::read_to_string(&conf).unwrap(), text);
        assert_eq!(
            std::fs::read_dir(site::challenge_dir(&root))
                .unwrap()
                .count(),
            0
        );

        // success: certificate installed, HTTPS on, challenge files cleaned up
        *fake.fail.lock().unwrap() = false;
        let v = call(&ctx, "cert_issue", json!({ "name": "app" }), false)
            .await
            .unwrap();
        assert_eq!(v["changed"], true);
        let text = std::fs::read_to_string(&conf).unwrap();
        assert!(text.contains("listen 443 ssl") && text.contains("return 301"));
        assert!(
            text.contains("acme-challenge"),
            "renewals need the challenge path"
        );
        assert_eq!(
            std::fs::read_dir(site::challenge_dir(&root))
                .unwrap()
                .count(),
            0
        );
        let sites = call(&ctx, "sites", json!({}), false).await.unwrap();
        assert!(sites["sites"][0]["cert"]["last_error"].is_null());
        assert_eq!(sites["sites"][0]["cert"]["names"][1], "www.app.example.com");

        // far from expiry: nothing to do unless forced, and the renewal sweep skips it
        let v = call(&ctx, "cert_issue", json!({ "name": "app" }), false)
            .await
            .unwrap();
        assert_eq!(v["changed"], false);
        assert!(renew_due(&ctx).await.is_empty());

        // a domain added later makes the certificate due even far from expiry
        let mut st = site::load_state(&ctx, "app").unwrap().unwrap();
        st.spec.domains.push("new.app.example.com".into());
        site::write_state(&ctx, &st).unwrap();
        let before = *fake.calls.lock().unwrap();
        assert_eq!(renew_due(&ctx).await, ["app"]);
        assert_eq!(*fake.calls.lock().unwrap(), before + 1);
        let info = cert_info(&root, &site::load_state(&ctx, "app").unwrap().unwrap());
        assert!(info.names.contains(&"new.app.example.com".to_string()));
        st.spec.domains.pop();
        site::write_state(&ctx, &st).unwrap();
        let calls = *fake.calls.lock().unwrap();

        // close to expiry: the sweep renews it
        let (c, k) = expiring(&["app.example.com", "www.app.example.com"], 10);
        let st = site::load_state(&ctx, "app").unwrap().unwrap();
        install(&ctx, &root, &st.spec, &c, &k).unwrap();
        assert_eq!(renew_due(&ctx).await, ["app"]);
        assert_eq!(*fake.calls.lock().unwrap(), calls + 1);
        let info = cert_info(&root, &site::load_state(&ctx, "app").unwrap().unwrap());
        assert!(
            days_left(
                info.not_after.unwrap(),
                chrono::Utc::now().timestamp_millis()
            ) > 60
        );
    }

    #[tokio::test]
    async fn acme_preflight_stops_before_the_ca() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("nginx");
        std::fs::create_dir_all(root.join("conf.d")).unwrap();
        // a server that does not serve the challenge directory
        let url = challenge_server(d.path().join("elsewhere")).await;
        let (ctx, fake) = acme_ctx(d.path(), &root, Some(url));
        let spec = json!({
            "name": "app",
            "domains": ["app.example.com"],
            "proxy": { "upstream": "http://127.0.0.1:3000" },
            "ssl": { "mode": "acme" },
        });
        call(&ctx, "site_save", json!({ "spec": spec }), false)
            .await
            .unwrap();
        let e = call(&ctx, "cert_issue", json!({ "name": "app" }), false)
            .await
            .unwrap_err();
        assert!(e.message.contains("自检失败"), "{e}");
        assert_eq!(*fake.calls.lock().unwrap(), 0);
        // and acme mode cannot be saved where ACME is off
        let (ctx2, _) = acme_ctx(d.path(), &root, None);
        let mut cfg = (*ctx2.cfg).clone();
        cfg.nginx.acme.enabled = false;
        let ctx3 = Ctx::new(cfg).unwrap();
        let e = call(&ctx3, "cert_issue", json!({ "name": "app" }), false)
            .await
            .unwrap_err();
        assert_eq!(e.code, crate::ops::proto::ErrorCode::NotAllowed);
    }

    #[test]
    fn parse_and_cover() {
        let (cert, key) = self_signed(&["a.example.com", "*.b.example.com"]);
        let p = parse_chain(cert.as_bytes()).unwrap();
        assert_eq!(p.names, ["a.example.com", "*.b.example.com"]);
        assert!(p.not_after > p.not_before);
        assert!(check_key(&key).is_ok());
        assert!(check_key(&cert).is_err());
        assert!(parse_chain(key.as_bytes()).is_err());
        assert!(parse_chain(b"garbage").is_err());
        assert!(covers("*.b.example.com", "x.b.example.com"));
        assert!(!covers("*.b.example.com", "b.example.com"));
        assert!(!covers("*.b.example.com", "y.x.b.example.com"));
    }

    #[tokio::test]
    async fn upload_installs_cert_and_enables_https() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("nginx");
        std::fs::create_dir_all(root.join("conf.d")).unwrap();
        let ctx = ctx_with(d.path(), &root, |n| {
            n.allow.push(NginxOp::Manage);
            n.allow.push(NginxOp::Cert);
        });
        let spec = json!({
            "name": "app",
            "domains": ["app.example.com"],
            "proxy": { "upstream": "http://127.0.0.1:3000" },
            "ssl": { "mode": "upload" },
        });
        call(&ctx, "site_save", json!({ "spec": spec }), false)
            .await
            .unwrap();
        let conf = root.join("conf.d/app.conf");
        assert!(!std::fs::read_to_string(&conf).unwrap().contains("443"));

        let (cert, key) = self_signed(&["app.example.com"]);
        let e = call(
            &ctx,
            "cert_upload",
            json!({ "name": "app", "cert_pem": cert, "key_pem": "nope" }),
            false,
        )
        .await
        .unwrap_err();
        assert!(e.message.contains("私钥"), "{e}");
        let v = call(
            &ctx,
            "cert_upload",
            json!({ "name": "app", "cert_pem": cert, "key_pem": key }),
            false,
        )
        .await
        .unwrap();
        assert!(!v.to_string().contains("PRIVATE KEY"));
        let text = std::fs::read_to_string(&conf).unwrap();
        assert!(text.contains("listen 443 ssl"), "{text}");
        assert!(text.contains("return 301"));
        use std::os::unix::fs::PermissionsExt;
        let keyfile = root.join("tsmonitor/certs/app/privkey.pem");
        assert_eq!(
            std::fs::metadata(&keyfile).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let sites = call(&ctx, "sites", json!({}), false).await.unwrap();
        let s = &sites["sites"][0];
        assert_eq!(s["cert"]["mode"], "upload");
        assert!(s["cert"]["not_after"].as_i64().unwrap() > 0);
        // the helper's own directory is not visible as config files
        let files = call(&ctx, "files", json!({}), false).await.unwrap();
        assert!(!files.to_string().contains("tsmonitor/"));
        assert!(
            call(&ctx, "file", json!({ "path": "tsmonitor/certs" }), false)
                .await
                .is_err()
        );

        // a broken result restores the previous certificate byte for byte
        let before = std::fs::read(&keyfile).unwrap();
        let conf_before = std::fs::read(&conf).unwrap();
        std::fs::write(root.join("conf.d/zz.conf"), "BROKEN").unwrap();
        let (cert2, key2) = self_signed(&["app.example.com"]);
        assert!(
            call(
                &ctx,
                "cert_upload",
                json!({ "name": "app", "cert_pem": cert2, "key_pem": key2 }),
                false,
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&keyfile).unwrap(), before);
        assert_eq!(std::fs::read(&conf).unwrap(), conf_before);
    }
}
