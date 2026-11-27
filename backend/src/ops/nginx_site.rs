//! Managed nginx sites: a structured description (`SiteSpec`) that the dashboard fills in as a
//! form, validated and rendered into a complete server config by the helper. The rendered file
//! starts with a marker line carrying the site name, its kind and a hash of the rest of the
//! file, so hand edits are detected from the file alone (the daemon cannot read the helper's
//! state directory).
//!
//! Rendering is pure: everything that depends on the host (whether a certificate exists, the
//! nginx version) comes in through [`RenderEnv`].

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::proto::{OpError, OpResult};
use super::validate;

/// First line of every managed config.
pub const MARKER: &str = "# tsmonitor-managed v1";
/// Directory under the nginx root for files the helper owns (certificates, challenges).
pub const OWN_DIR: &str = "tsmonitor";
/// Largest `extra` snippet.
const MAX_EXTRA: usize = 16 * 1024;
const MAX_DOMAINS: usize = 50;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SiteKind {
    /// Forwards every request to an upstream URL.
    #[default]
    Proxy,
    /// Serves files from a directory.
    Static,
}

impl SiteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SiteKind::Proxy => "proxy",
            SiteKind::Static => "static",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyOpts {
    /// `http://127.0.0.1:3000` or `https://backend.internal/app`.
    pub upstream: String,
    /// Pass `Upgrade` / `Connection` so WebSocket connections work.
    pub websocket: bool,
    /// Send the client's `Host` header upstream (off: the upstream's own host name).
    pub pass_host: bool,
    /// proxy_read_timeout / proxy_send_timeout.
    pub timeout_secs: u32,
}

impl Default for ProxyOpts {
    fn default() -> Self {
        Self {
            upstream: String::new(),
            websocket: false,
            pass_host: true,
            timeout_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct StaticOpts {
    /// Absolute document root; must lie under one of the helper's `site_roots`.
    pub root: String,
    /// Space-separated index files.
    pub index: String,
    /// Single-page app: unknown paths fall back to `/index.html`.
    pub spa: bool,
}

impl Default for StaticOpts {
    fn default() -> Self {
        Self {
            root: String::new(),
            index: "index.html index.htm".into(),
            spa: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ListenOpts {
    pub http: u16,
    pub https: u16,
    /// Also listen on `[::]`.
    pub ipv6: bool,
}

impl Default for ListenOpts {
    fn default() -> Self {
        Self {
            http: 80,
            https: 443,
            ipv6: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Features {
    /// Redirect HTTP to HTTPS (only once a certificate is in place).
    pub force_https: bool,
    pub http2: bool,
    /// Strict-Transport-Security (only on HTTPS).
    pub hsts: bool,
    pub gzip: bool,
    /// Long cache headers for images, fonts, CSS and JS (static sites).
    pub static_cache: bool,
    /// Separate access and error logs under /var/log/nginx/.
    pub access_log: bool,
    /// client_max_body_size in MiB; 0 keeps nginx's default (1 MiB).
    pub client_max_body_mb: u32,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            force_https: true,
            http2: true,
            hsts: false,
            gzip: true,
            static_cache: true,
            access_log: true,
            client_max_body_mb: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SslMode {
    #[default]
    None,
    /// Issued and renewed by the helper (ACME HTTP-01).
    Acme,
    /// Uploaded through the dashboard.
    Upload,
    /// A certificate that already exists on the server (e.g. from certbot).
    Path,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct SslOpts {
    pub mode: SslMode,
    /// `path` mode only.
    pub cert_path: String,
    /// `path` mode only.
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct SiteSpec {
    /// Config file name; also names the certificate directory and log files. Not renamable.
    pub name: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub kind: SiteKind,
    #[serde(default)]
    pub proxy: ProxyOpts,
    #[serde(default, rename = "static")]
    pub static_site: StaticOpts,
    #[serde(default)]
    pub listen: ListenOpts,
    #[serde(default)]
    pub features: Features,
    #[serde(default)]
    pub ssl: SslOpts,
    /// Extra directives appended to the serving `server` block. Needs the `edit` permission.
    #[serde(default)]
    pub extra: String,
}

/// Certificate state of a managed site, as reported in `nginx.sites`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct CertInfo {
    pub mode: SslMode,
    /// Expiry of the installed certificate (ms since epoch); none = not issued yet.
    pub not_after: Option<i64>,
    pub not_before: Option<i64>,
    /// DNS names the certificate covers.
    pub names: Vec<String>,
    pub issuer: Option<String>,
    /// Last issuance or renewal attempt (ms) and its error, if it failed.
    pub last_attempt: Option<i64>,
    pub last_error: Option<String>,
}

/// Host facts the renderer needs.
#[derive(Debug, Clone, Default)]
pub struct RenderEnv {
    /// (fullchain, private key) absolute paths when a usable certificate exists.
    pub cert: Option<(String, String)>,
    /// Absolute directory served at `/.well-known/acme-challenge/` (with trailing slash).
    pub challenge_dir: String,
    /// nginx >= 1.25.1 understands `http2 on;`; older versions need `listen ... http2`.
    pub http2_directive: bool,
}

fn bad(msg: impl Into<String>) -> OpError {
    OpError::invalid(msg)
}

/// Site name: a file name that cannot be confused with the conf.d suffixes.
pub fn site_name(s: &str) -> OpResult<&str> {
    validate::file_name(s).map_err(|_| {
        bad(format!(
            "无效的站点名：{s:?}（只能包含字母、数字、. _ -，不能以 . 开头）"
        ))
    })?;
    if s.len() > 64 {
        return Err(bad("站点名最长 64 个字符"));
    }
    if s.ends_with(".conf") || s.ends_with(".disabled") || s == OWN_DIR {
        return Err(bad(format!("站点名不能是 {s:?}")));
    }
    Ok(s)
}

/// A server_name entry: a host name (optionally `*.` wildcard) or an IPv4 address.
pub fn server_name(s: &str) -> OpResult<String> {
    let s = s.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = s.strip_prefix("*.").unwrap_or(&s);
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
    };
    let ok = !host.is_empty()
        && s.len() <= 253
        && (host.parse::<std::net::Ipv4Addr>().is_ok() && !s.starts_with("*.")
            || host.split('.').all(label_ok));
    ok.then_some(s.clone())
        .ok_or_else(|| bad(format!("无效的域名：{s:?}")))
}

/// Upstream URL for proxy_pass: http(s) with a host, no characters that could break out of
/// the directive.
pub fn upstream_url(s: &str) -> OpResult<String> {
    let s = s.trim();
    if s.is_empty() {
        return Err(bad("请填写反向代理的目标地址"));
    }
    if s.len() > 512
        || s.chars()
            .any(|c| c.is_whitespace() || c.is_control() || ";{}#\"'\\$`".contains(c))
    {
        return Err(bad(format!("目标地址包含不允许的字符：{s:?}")));
    }
    let u = url::Url::parse(s).map_err(|e| bad(format!("目标地址无效：{e}")))?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none_or(str::is_empty) {
        return Err(bad("目标地址必须是 http:// 或 https:// 开头的完整地址"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(bad("目标地址不能包含用户名或密码"));
    }
    Ok(s.to_string())
}

/// Absolute path made of [`validate::file_name`] components.
pub fn abs_path(what: &str, s: &str) -> OpResult<String> {
    let s = s.trim().trim_end_matches('/');
    let rest = s
        .strip_prefix('/')
        .ok_or_else(|| bad(format!("{what}必须是绝对路径")))?;
    if rest.is_empty() || s.len() > 256 {
        return Err(bad(format!("{what}无效：{s:?}")));
    }
    for c in rest.split('/') {
        let ok = !c.is_empty()
            && c != "."
            && c != ".."
            && c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
        if !ok {
            return Err(bad(format!("{what}无效：{s:?}")));
        }
    }
    Ok(s.to_string())
}

/// True when `path` equals `root` or lies below it.
pub fn under(path: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    path == root || path.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
}

fn balanced(text: &str) -> bool {
    let mut depth = 0i32;
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or("");
        for c in code.chars() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth < 0 {
                        return false;
                    }
                }
                _ => {}
            }
        }
    }
    depth == 0
}

impl SiteSpec {
    /// Checks and normalises the spec. Host-dependent limits (allowed document roots and
    /// certificate locations, the `edit` permission for `extra`) are checked by the helper.
    pub fn normalize(&mut self) -> OpResult<()> {
        site_name(&self.name)?;
        let mut domains: Vec<String> = Vec::new();
        for d in &self.domains {
            if d.trim().is_empty() {
                continue;
            }
            let d = server_name(d)?;
            if !domains.contains(&d) {
                domains.push(d);
            }
        }
        if domains.is_empty() {
            return Err(bad("至少需要绑定一个域名"));
        }
        if domains.len() > MAX_DOMAINS {
            return Err(bad(format!("一个站点最多绑定 {MAX_DOMAINS} 个域名")));
        }
        self.domains = domains;
        match self.kind {
            SiteKind::Proxy => {
                self.proxy.upstream = upstream_url(&self.proxy.upstream)?;
                if !(1..=3600).contains(&self.proxy.timeout_secs) {
                    return Err(bad("代理超时必须在 1 到 3600 秒之间"));
                }
            }
            SiteKind::Static => {
                self.static_site.root = abs_path("网站根目录", &self.static_site.root)?;
                let idx: Vec<&str> = self.static_site.index.split_whitespace().collect();
                if idx.is_empty() {
                    self.static_site.index = StaticOpts::default().index;
                } else {
                    for f in &idx {
                        validate::file_name(f)
                            .map_err(|_| bad(format!("无效的首页文件名：{f:?}")))?;
                    }
                    self.static_site.index = idx.join(" ");
                }
            }
        }
        let l = &self.listen;
        if l.http == 0 || l.https == 0 || l.http == l.https {
            return Err(bad("HTTP 与 HTTPS 端口必须是 1-65535 之间且互不相同"));
        }
        if self.features.client_max_body_mb > 10 * 1024 {
            return Err(bad("上传大小限制最大 10240 MiB"));
        }
        match self.ssl.mode {
            SslMode::Path => {
                self.ssl.cert_path = abs_path("证书路径", &self.ssl.cert_path)?;
                self.ssl.key_path = abs_path("私钥路径", &self.ssl.key_path)?;
            }
            _ => {
                self.ssl.cert_path.clear();
                self.ssl.key_path.clear();
            }
        }
        if self.ssl.mode == SslMode::Acme {
            if self.listen.http != 80 {
                return Err(bad("自动申请证书使用 HTTP-01 验证，站点必须监听 80 端口"));
            }
            if let Some(w) = self.domains.iter().find(|d| d.starts_with("*.")) {
                return Err(bad(format!(
                    "通配符域名 {w} 无法通过 HTTP 验证申请证书，请改用上传证书"
                )));
            }
            if let Some(ip) = self
                .domains
                .iter()
                .find(|d| d.parse::<std::net::Ipv4Addr>().is_ok())
            {
                return Err(bad(format!("IP 地址 {ip} 不能申请证书")));
            }
        }
        self.extra = self.extra.trim_end().to_string();
        if !self.extra.is_empty() {
            if self.extra.len() > MAX_EXTRA {
                return Err(bad("自定义配置最多 16 KiB"));
            }
            if !balanced(&self.extra) {
                return Err(bad("自定义配置中的花括号不配对"));
            }
            super::nginx::check_directives(&self.extra)?;
        }
        Ok(())
    }

    /// Paths of the files the helper writes for uploaded and issued certificates,
    /// relative to the nginx root.
    pub fn managed_cert_rel(&self) -> (String, String) {
        let d = format!("{OWN_DIR}/certs/{}", self.name);
        (format!("{d}/fullchain.pem"), format!("{d}/privkey.pem"))
    }
}

/// The header line, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    pub name: String,
    pub kind: Option<SiteKind>,
    /// The body no longer matches the hash written with it.
    pub drifted: bool,
}

fn body_hash(body: &str) -> String {
    crate::helper::fsutil::sha256_hex(body.as_bytes())
}

pub fn parse_marker(text: &str) -> Option<Marker> {
    let (first, body) = text.split_once('\n').unwrap_or((text, ""));
    let rest = first.strip_prefix(MARKER)?;
    let mut name = None;
    let mut kind = None;
    let mut sha = None;
    for kv in rest.split_whitespace() {
        match kv.split_once('=') {
            Some(("name", v)) => name = Some(v.to_string()),
            Some(("kind", "proxy")) => kind = Some(SiteKind::Proxy),
            Some(("kind", "static")) => kind = Some(SiteKind::Static),
            Some(("sha256", v)) => sha = Some(v.to_string()),
            _ => {}
        }
    }
    Some(Marker {
        name: name?,
        kind,
        drifted: sha.is_none_or(|s| s != body_hash(body)),
    })
}

/// Renders the complete config file for `spec` (which must have passed
/// [`SiteSpec::normalize`]).
pub fn render(spec: &SiteSpec, env: &RenderEnv) -> String {
    let mut b = String::new();
    let names = spec.domains.join(" ");
    let f = &spec.features;
    let tls = spec.ssl.mode != SslMode::None;
    let cert = env.cert.as_ref().filter(|_| tls);
    let _ = writeln!(
        b,
        "# 由 TServerMonitor 生成。请在面板的 nginx 站点中修改；手动改动会在下次保存时提示覆盖。"
    );
    if tls && cert.is_none() {
        let _ = writeln!(
            b,
            "# 证书尚未就绪：暂时只提供 HTTP，证书就绪后自动启用 HTTPS。"
        );
    }

    // port 80 server: challenge, then a redirect or the site itself
    let _ = writeln!(b, "server {{");
    listen(&mut b, spec.listen.http, spec.listen.ipv6, "");
    let _ = writeln!(b, "    server_name {names};");
    if spec.ssl.mode == SslMode::Acme {
        let _ = writeln!(b);
        let _ = writeln!(b, "    location ^~ /.well-known/acme-challenge/ {{");
        let _ = writeln!(b, "        alias {};", env.challenge_dir);
        let _ = writeln!(b, "        default_type text/plain;");
        let _ = writeln!(b, "    }}");
    }
    let redirect = cert.is_some() && f.force_https;
    if redirect {
        logs(&mut b, spec);
        let _ = writeln!(b);
        let port = if spec.listen.https == 443 {
            String::new()
        } else {
            format!(":{}", spec.listen.https)
        };
        let _ = writeln!(b, "    location / {{");
        let _ = writeln!(b, "        return 301 https://$host{port}$request_uri;");
        let _ = writeln!(b, "    }}");
    } else {
        site_body(&mut b, spec);
    }
    let _ = writeln!(b, "}}");

    if let Some((chain, key)) = cert {
        let h2 = f.http2 && !env.http2_directive;
        let _ = writeln!(b);
        let _ = writeln!(b, "server {{");
        let opts = if h2 { " ssl http2" } else { " ssl" };
        listen(&mut b, spec.listen.https, spec.listen.ipv6, opts);
        if f.http2 && env.http2_directive {
            let _ = writeln!(b, "    http2 on;");
        }
        let _ = writeln!(b, "    server_name {names};");
        let _ = writeln!(b);
        let _ = writeln!(b, "    ssl_certificate {chain};");
        let _ = writeln!(b, "    ssl_certificate_key {key};");
        let _ = writeln!(b, "    ssl_protocols TLSv1.2 TLSv1.3;");
        let _ = writeln!(b, "    ssl_prefer_server_ciphers off;");
        let _ = writeln!(b, "    ssl_session_timeout 1d;");
        let _ = writeln!(b, "    ssl_session_cache shared:tsm_ssl:10m;");
        if f.hsts {
            let _ = writeln!(
                b,
                "    add_header Strict-Transport-Security \"max-age=31536000\" always;"
            );
        }
        site_body(&mut b, spec);
        let _ = writeln!(b, "}}");
    }

    let header = format!(
        "{MARKER} name={} kind={} sha256={}\n",
        spec.name,
        spec.kind.as_str(),
        body_hash(&b)
    );
    header + &b
}

fn listen(b: &mut String, port: u16, ipv6: bool, opts: &str) {
    let _ = writeln!(b, "    listen {port}{opts};");
    if ipv6 {
        let _ = writeln!(b, "    listen [::]:{port}{opts};");
    }
}

fn logs(b: &mut String, spec: &SiteSpec) {
    if spec.features.access_log {
        let _ = writeln!(b, "    access_log /var/log/nginx/{}.access.log;", spec.name);
        let _ = writeln!(b, "    error_log /var/log/nginx/{}.error.log;", spec.name);
    }
}

/// Everything that serves the site: shared settings, then the kind-specific locations.
fn site_body(b: &mut String, spec: &SiteSpec) {
    let f = &spec.features;
    logs(b, spec);
    if f.client_max_body_mb > 0 {
        let _ = writeln!(b, "    client_max_body_size {}m;", f.client_max_body_mb);
    }
    if f.gzip {
        let _ = writeln!(b);
        let _ = writeln!(b, "    gzip on;");
        let _ = writeln!(b, "    gzip_vary on;");
        let _ = writeln!(b, "    gzip_min_length 1024;");
        let _ = writeln!(b, "    gzip_proxied any;");
        let _ = writeln!(
            b,
            "    gzip_types text/plain text/css text/xml application/json application/javascript application/xml image/svg+xml;"
        );
    }
    let _ = writeln!(b);
    match spec.kind {
        SiteKind::Proxy => {
            let p = &spec.proxy;
            let _ = writeln!(b, "    location / {{");
            let _ = writeln!(b, "        proxy_pass {};", p.upstream);
            let _ = writeln!(b, "        proxy_http_version 1.1;");
            let host = if p.pass_host { "$host" } else { "$proxy_host" };
            let _ = writeln!(b, "        proxy_set_header Host {host};");
            let _ = writeln!(b, "        proxy_set_header X-Real-IP $remote_addr;");
            let _ = writeln!(
                b,
                "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
            );
            let _ = writeln!(b, "        proxy_set_header X-Forwarded-Proto $scheme;");
            if p.websocket {
                let _ = writeln!(b, "        proxy_set_header Upgrade $http_upgrade;");
                let _ = writeln!(b, "        proxy_set_header Connection \"upgrade\";");
            }
            let _ = writeln!(b, "        proxy_read_timeout {}s;", p.timeout_secs);
            let _ = writeln!(b, "        proxy_send_timeout {}s;", p.timeout_secs);
            let _ = writeln!(b, "    }}");
        }
        SiteKind::Static => {
            let s = &spec.static_site;
            let _ = writeln!(b, "    root {};", s.root);
            let _ = writeln!(b, "    index {};", s.index);
            let _ = writeln!(b);
            let _ = writeln!(b, "    location / {{");
            let fallback = if s.spa { "/index.html" } else { "=404" };
            let _ = writeln!(b, "        try_files $uri $uri/ {fallback};");
            let _ = writeln!(b, "    }}");
            if f.static_cache {
                let _ = writeln!(b);
                let _ = writeln!(
                    b,
                    "    location ~* \\.(?:css|js|mjs|png|jpe?g|gif|ico|svg|webp|avif|woff2?|ttf)$ {{"
                );
                let _ = writeln!(b, "        expires 30d;");
                let _ = writeln!(b, "        add_header Cache-Control \"public\";");
                let _ = writeln!(b, "        try_files $uri =404;");
                let _ = writeln!(b, "    }}");
            }
            let _ = writeln!(b);
            let _ = writeln!(b, "    location ~ /\\.(?!well-known) {{");
            let _ = writeln!(b, "        deny all;");
            let _ = writeln!(b, "    }}");
        }
    }
    if !spec.extra.is_empty() {
        let _ = writeln!(b);
        let _ = writeln!(b, "    # 自定义配置");
        for l in spec.extra.lines() {
            if l.trim().is_empty() {
                let _ = writeln!(b);
            } else {
                let _ = writeln!(b, "    {}", l.trim_end());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy() -> SiteSpec {
        SiteSpec {
            name: "app".into(),
            domains: vec![
                "App.Example.com".into(),
                "www.example.com".into(),
                " ".into(),
            ],
            proxy: ProxyOpts {
                upstream: "http://127.0.0.1:3000".into(),
                websocket: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn env_with_cert() -> RenderEnv {
        RenderEnv {
            cert: Some((
                "/etc/nginx/tsmonitor/certs/app/fullchain.pem".into(),
                "/etc/nginx/tsmonitor/certs/app/privkey.pem".into(),
            )),
            challenge_dir: "/etc/nginx/tsmonitor/acme-challenge/".into(),
            http2_directive: true,
        }
    }

    #[test]
    fn spec_json_defaults_and_unknown_fields() {
        let s: SiteSpec = serde_json::from_value(serde_json::json!({
            "name": "a", "domains": ["a.com"], "kind": "static", "static": { "root": "/var/www/a" }
        }))
        .unwrap();
        assert_eq!(s.kind, SiteKind::Static);
        assert_eq!(s.static_site.index, "index.html index.htm");
        assert!(s.proxy.pass_host && s.features.gzip && s.listen.http == 80);
        assert!(
            serde_json::from_value::<SiteSpec>(
                serde_json::json!({ "name": "a", "domains": [], "bogus": 1 })
            )
            .is_err()
        );
    }

    #[test]
    fn validation() {
        let mut s = proxy();
        s.normalize().unwrap();
        assert_eq!(s.domains, ["app.example.com", "www.example.com"]);

        type Case = Box<dyn Fn(&mut SiteSpec)>;
        let cases: Vec<Case> = vec![
            Box::new(|s| s.name = "../x".into()),
            Box::new(|s| s.name = "x.conf".into()),
            Box::new(|s| s.name = "tsmonitor".into()),
            Box::new(|s| s.domains = vec![]),
            Box::new(|s| s.domains = vec!["a b.com".into()]),
            Box::new(|s| s.domains = vec!["a.com;evil".into()]),
            Box::new(|s| s.domains = vec!["-a.com".into()]),
            Box::new(|s| s.proxy.upstream = "http://x;y".into()),
            Box::new(|s| s.proxy.upstream = "http://a $b".into()),
            Box::new(|s| s.proxy.upstream = "unix:/run/app.sock".into()),
            Box::new(|s| s.proxy.upstream = "http://u:p@host".into()),
            Box::new(|s| s.proxy.timeout_secs = 0),
            Box::new(|s| s.listen.https = 80),
            Box::new(|s| {
                s.ssl.mode = SslMode::Acme;
                s.listen.http = 8080;
            }),
            Box::new(|s| {
                s.ssl.mode = SslMode::Acme;
                s.domains = vec!["*.example.com".into()];
            }),
            Box::new(|s| {
                s.ssl.mode = SslMode::Path;
                s.ssl.cert_path = "relative/x.pem".into();
            }),
            Box::new(|s| s.extra = "location / {".into()),
            Box::new(|s| s.extra = "load_module x.so;".into()),
            Box::new(|s| {
                s.kind = SiteKind::Static;
                s.static_site.root = "/var/www/../etc".into();
            }),
            Box::new(|s| {
                s.kind = SiteKind::Static;
                s.static_site.root = "/var/www/a".into();
                s.static_site.index = "a;b".into();
            }),
        ];
        for (i, c) in cases.iter().enumerate() {
            let mut s = proxy();
            c(&mut s);
            assert!(s.normalize().is_err(), "case {i} should fail");
        }
        assert!(server_name("*.example.com").is_ok());
        assert!(server_name("10.0.0.1").is_ok());
        assert!(under("/var/www/a", "/var/www") && under("/var/www", "/var/www/"));
        assert!(!under("/var/wwwx", "/var/www"));
    }

    #[test]
    fn render_http_only_proxy() {
        let mut s = proxy();
        s.normalize().unwrap();
        let out = render(&s, &RenderEnv::default());
        let m = parse_marker(&out).unwrap();
        assert_eq!(m.name, "app");
        assert_eq!(m.kind, Some(SiteKind::Proxy));
        assert!(!m.drifted);
        assert!(out.contains("    listen 80;\n"));
        assert!(out.contains("server_name app.example.com www.example.com;"));
        assert!(out.contains("proxy_pass http://127.0.0.1:3000;"));
        assert!(out.contains("proxy_set_header Upgrade $http_upgrade;"));
        assert!(out.contains("access_log /var/log/nginx/app.access.log;"));
        assert!(!out.contains("443") && !out.contains("acme-challenge"));
        // a hand edit is detected
        let edited = out.replace("3000", "4000");
        assert!(parse_marker(&edited).unwrap().drifted);
        assert!(parse_marker("server {}").is_none());
    }

    #[test]
    fn render_tls_with_redirect_and_challenge() {
        let mut s = proxy();
        s.ssl.mode = SslMode::Acme;
        s.features.hsts = true;
        s.listen.ipv6 = true;
        s.normalize().unwrap();
        // no certificate yet: HTTP only, challenge location present, no redirect
        let pending = render(
            &s,
            &RenderEnv {
                cert: None,
                ..env_with_cert()
            },
        );
        assert!(pending.contains("证书尚未就绪"));
        assert!(pending.contains("alias /etc/nginx/tsmonitor/acme-challenge/;"));
        assert!(!pending.contains("return 301") && !pending.contains("listen 443"));

        let out = render(&s, &env_with_cert());
        assert!(out.contains("return 301 https://$host$request_uri;"));
        assert!(out.contains("    listen 443 ssl;\n    listen [::]:443 ssl;\n    http2 on;"));
        assert!(out.contains("ssl_certificate /etc/nginx/tsmonitor/certs/app/fullchain.pem;"));
        assert!(out.contains("Strict-Transport-Security"));
        // the redirect server must still answer challenges for renewals
        let first = out.split("server {").nth(1).unwrap();
        assert!(first.contains("acme-challenge") && first.contains("return 301"));
        assert!(!first.contains("proxy_pass"));

        // old nginx: http2 on the listen line
        let old = render(
            &s,
            &RenderEnv {
                http2_directive: false,
                ..env_with_cert()
            },
        );
        assert!(old.contains("listen 443 ssl http2;") && !old.contains("http2 on;"));

        // non-default https port in the redirect; no redirect when force_https is off
        s.listen.https = 8443;
        assert!(render(&s, &env_with_cert()).contains("https://$host:8443$request_uri"));
        s.features.force_https = false;
        let both = render(&s, &env_with_cert());
        assert_eq!(both.matches("proxy_pass").count(), 2);
    }

    #[test]
    fn render_static_site() {
        let mut s = SiteSpec {
            name: "docs".into(),
            domains: vec!["docs.example.com".into()],
            kind: SiteKind::Static,
            static_site: StaticOpts {
                root: "/var/www/docs/".into(),
                spa: true,
                ..Default::default()
            },
            features: Features {
                client_max_body_mb: 20,
                access_log: false,
                ..Default::default()
            },
            extra: "location /api/ {\n    return 404;\n}\n".into(),
            ..Default::default()
        };
        s.normalize().unwrap();
        let out = render(&s, &RenderEnv::default());
        assert!(out.contains("    root /var/www/docs;\n    index index.html index.htm;"));
        assert!(out.contains("try_files $uri $uri/ /index.html;"));
        assert!(out.contains("expires 30d;"));
        assert!(out.contains("client_max_body_size 20m;"));
        assert!(!out.contains("access_log"));
        assert!(
            out.contains("    # 自定义配置\n    location /api/ {\n        return 404;\n    }\n")
        );
        assert_eq!(parse_marker(&out).unwrap().kind, Some(SiteKind::Static));
    }

    #[test]
    fn every_rendering_passes_the_directive_guard() {
        for kind in [SiteKind::Proxy, SiteKind::Static] {
            for mode in [SslMode::None, SslMode::Acme, SslMode::Upload] {
                for flags in 0u8..16 {
                    let mut s = proxy();
                    s.kind = kind;
                    s.static_site.root = "/var/www/app".into();
                    s.ssl.mode = mode;
                    s.features.gzip = flags & 1 != 0;
                    s.features.access_log = flags & 2 != 0;
                    s.features.force_https = flags & 4 != 0;
                    s.listen.ipv6 = flags & 8 != 0;
                    s.normalize().unwrap();
                    for env in [RenderEnv::default(), env_with_cert()] {
                        let out = render(&s, &env);
                        super::super::nginx::check_directives(&out).unwrap();
                        assert!(balanced(&out), "{out}");
                    }
                }
            }
        }
    }
}
