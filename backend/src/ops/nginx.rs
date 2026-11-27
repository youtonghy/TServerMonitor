//! nginx configuration inventory shared by the helper and the daemon: site discovery for both
//! the Debian (`sites-available` + `sites-enabled`) and the `conf.d` layout, confined file
//! reads, and the directive guard applied before the helper writes a file.

use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use super::nginx_site::{self, CertInfo, SiteKind};
use super::proto::{OpError, OpResult};
use super::validate;

/// Largest config file read or written.
pub const MAX_FILE: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// `sites-available/NAME` enabled by a symlink in `sites-enabled/`.
    SitesEnabled,
    /// `conf.d/NAME.conf`, disabled by renaming to `NAME.conf.disabled`.
    ConfD,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub name: String,
    /// Path relative to the nginx root.
    pub file: String,
    pub enabled: bool,
    pub layout: Layout,
    pub server_names: Vec<String>,
    pub listen: Vec<String>,
    pub ssl: bool,
    /// Generated from a [`SiteSpec`](super::nginx_site::SiteSpec) by the helper.
    #[serde(default)]
    pub managed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<SiteKind>,
    /// A managed file that was edited by hand since it was generated.
    #[serde(default)]
    pub drifted: bool,
    /// Certificate state of a managed site (filled in by the helper).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub editable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileView {
    pub path: String,
    pub content: String,
    pub sha256: String,
    pub editable: bool,
}

static SERVER_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[\s{;])server_name\s+([^;{}]+);").expect("regex"));
static LISTEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[\s{;])listen\s+([^;{}]+);").expect("regex"));

/// Files never shown: keys, certificates, password files.
fn secret_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [".key", ".pem", ".crt", ".p12", ".pfx", ".der"]
        .iter()
        .any(|x| n.ends_with(x))
        || n.contains("htpasswd")
        || n.contains("passwd")
}

fn strip_comments(text: &str) -> String {
    text.lines()
        .map(|l| l.split_once('#').map_or(l, |(a, _)| a))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn site_info(text: &str) -> (Vec<String>, Vec<String>, bool) {
    let t = strip_comments(text);
    let mut names = Vec::new();
    for c in SERVER_NAME.captures_iter(&t) {
        for n in c[1].split_whitespace() {
            if !names.iter().any(|x| x == n) {
                names.push(n.to_string());
            }
        }
    }
    let listen: Vec<String> = LISTEN
        .captures_iter(&t)
        .map(|c| c[1].split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    let ssl = listen
        .iter()
        .any(|l| l.contains("ssl") || l.contains("443"));
    (names, listen, ssl)
}

pub fn layout(root: &Path) -> Layout {
    if root.join("sites-available").is_dir() {
        Layout::SitesEnabled
    } else {
        Layout::ConfD
    }
}

fn read_capped(p: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.is_file() || m.len() as usize > MAX_FILE {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

fn site(name: String, file: String, enabled: bool, layout: Layout, text: &str) -> Site {
    let (server_names, listen, ssl) = site_info(text);
    // only a marker naming this very file counts; a copied managed file is a manual site
    let marker = nginx_site::parse_marker(text).filter(|m| m.name == name);
    Site {
        name,
        file,
        enabled,
        layout,
        server_names,
        listen,
        ssl,
        managed: marker.is_some(),
        kind: marker.as_ref().and_then(|m| m.kind),
        drifted: marker.is_some_and(|m| m.drifted),
        cert: None,
    }
}

pub fn sites(root: &Path) -> Vec<Site> {
    let mut out = Vec::new();
    let avail = root.join("sites-available");
    if avail.is_dir() {
        let enabled_dir = root.join("sites-enabled");
        for e in std::fs::read_dir(&avail).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if validate::file_name(&name).is_err() {
                continue;
            }
            let path = e.path();
            let Some(text) = read_capped(&path) else {
                continue;
            };
            let link = enabled_dir.join(&name);
            let enabled = std::fs::read_link(&link).is_ok_and(|t| {
                let t = if t.is_absolute() {
                    t
                } else {
                    enabled_dir.join(t)
                };
                t.file_name() == path.file_name()
            }) || std::fs::symlink_metadata(&link).is_ok_and(|m| m.is_file());
            out.push(site(
                name.clone(),
                format!("sites-available/{name}"),
                enabled,
                Layout::SitesEnabled,
                &text,
            ));
        }
    }
    let confd = root.join("conf.d");
    for e in std::fs::read_dir(&confd).into_iter().flatten().flatten() {
        let fname = e.file_name().to_string_lossy().into_owned();
        let (name, enabled) = if let Some(n) = fname.strip_suffix(".conf.disabled") {
            (n.to_string(), false)
        } else if let Some(n) = fname.strip_suffix(".conf") {
            (n.to_string(), true)
        } else {
            continue;
        };
        if validate::file_name(&fname).is_err() {
            continue;
        }
        let Some(text) = read_capped(&e.path()) else {
            continue;
        };
        let s = site(
            name,
            format!("conf.d/{fname}"),
            enabled,
            Layout::ConfD,
            &text,
        );
        // conf.d also holds global snippets; only files with a server block are sites
        if s.listen.is_empty() && s.server_names.is_empty() {
            continue;
        }
        out.push(s);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Readable config files: `nginx.conf` and everything (non-secret) one level below the root.
pub fn files(root: &Path, edit_dirs: &[String]) -> Vec<FileEntry> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if validate::file_name(&name).is_err() || secret_name(&name) {
            continue;
        }
        let Ok(m) = e.path().symlink_metadata() else {
            continue;
        };
        if m.is_file() {
            out.push(FileEntry {
                path: name,
                size: m.len(),
                editable: false,
            });
        } else if m.is_dir() && name != "sites-enabled" && name != nginx_site::OWN_DIR {
            let editable = edit_dirs.iter().any(|d| d == &name);
            for f in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
                let fname = f.file_name().to_string_lossy().into_owned();
                if validate::file_name(&fname).is_err() || secret_name(&fname) {
                    continue;
                }
                let Ok(fm) = f.path().symlink_metadata() else {
                    continue;
                };
                if fm.is_file() {
                    out.push(FileEntry {
                        path: format!("{name}/{fname}"),
                        size: fm.len(),
                        editable,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Validates `rel` for reading (any depth-1/2 non-secret file) or writing (inside `edit_dirs`).
pub fn check_path(rel: &str, edit_dirs: &[String], write: bool) -> OpResult<Vec<String>> {
    let parts = validate::rel_path(rel)?;
    if parts.len() > 2 {
        return Err(OpError::invalid("只能访问 nginx 根目录下两层以内的文件"));
    }
    if parts.iter().any(|p| secret_name(p)) || parts[0] == nginx_site::OWN_DIR {
        return Err(OpError::invalid("证书、私钥与密码文件不允许通过面板访问"));
    }
    if write {
        if parts.len() != 2 || !edit_dirs.iter().any(|d| d == &parts[0]) {
            return Err(OpError::invalid(format!(
                "只能编辑这些目录中的文件：{}",
                edit_dirs.join(", ")
            )));
        }
        let n = &parts[1];
        if parts[0] != "sites-available" && !n.ends_with(".conf") {
            return Err(OpError::invalid(
                "conf.d 与 snippets 中的文件必须以 .conf 结尾",
            ));
        }
    }
    Ok(parts)
}

pub fn read_file(root: &Path, rel: &str, edit_dirs: &[String]) -> OpResult<FileView> {
    let parts = check_path(rel, edit_dirs, false)?;
    let mut p = PathBuf::from(root);
    for (i, c) in parts.iter().enumerate() {
        p.push(c);
        let m =
            std::fs::symlink_metadata(&p).map_err(|_| OpError::invalid(format!("{rel} 不存在")))?;
        if m.file_type().is_symlink() {
            return Err(OpError::invalid(format!("{rel} 是符号链接")));
        }
        if i + 1 == parts.len() && (!m.is_file() || m.len() as usize > MAX_FILE) {
            return Err(OpError::invalid(format!(
                "{rel} 不是普通文件或超过 512 KiB"
            )));
        }
    }
    let data = std::fs::read(&p).map_err(|e| OpError::failed(format!("读取 {rel}：{e}")))?;
    let content = String::from_utf8(data.clone())
        .map_err(|_| OpError::invalid(format!("{rel} 不是 UTF-8 文本")))?;
    let editable = check_path(rel, edit_dirs, true).is_ok();
    Ok(FileView {
        path: rel.to_string(),
        sha256: crate::helper::fsutil::sha256_hex(&data),
        content,
        editable,
    })
}

/// Best-effort guard against directives that turn a config edit into code execution or
/// arbitrary file writes as root. nginx config editing stays root-equivalent; this only
/// removes the obvious paths.
pub fn check_directives(text: &str) -> OpResult<()> {
    let t = strip_comments(text);
    for raw in t.split([';', '{', '}']) {
        let stmt = raw.trim();
        let mut words = stmt.split_whitespace();
        let Some(d) = words.next() else { continue };
        let d = d.to_ascii_lowercase();
        let first_arg = words.next().unwrap_or("").trim_matches(['"', '\'']);
        let deny = |why: &str| -> OpResult<()> {
            Err(OpError::invalid(format!("拒绝写入：指令 {d} {why}")))
        };
        if matches!(
            d.as_str(),
            "load_module" | "user" | "env" | "pid" | "lock_file"
        ) || d.starts_with("perl")
            || d.starts_with("js_")
            || d.starts_with("lua_")
            || d.contains("_by_lua")
        {
            deny("可在 root 权限下执行代码或改变进程身份，只能在服务器上手动修改")?;
        }
        if matches!(d.as_str(), "access_log" | "error_log")
            && !(first_arg == "off"
                || first_arg.starts_with("syslog:")
                || first_arg == "stderr"
                || first_arg.starts_with("memory:")
                || (first_arg.starts_with("/var/log/") && !first_arg.contains("..")))
        {
            deny("的路径必须位于 /var/log/ 下（nginx 主进程以 root 打开日志文件）")?;
        }
        if d.ends_with("_temp_path") && !first_arg.starts_with("/var/") {
            deny("的路径必须位于 /var/ 下")?;
        }
        if d == "include"
            && first_arg.starts_with('/')
            && !(first_arg.starts_with("/etc/nginx/") || first_arg.starts_with("/usr/share/nginx/"))
        {
            deny("只能引用 /etc/nginx 或 /usr/share/nginx 下的文件")?;
        }
        if first_arg.contains("..") && matches!(d.as_str(), "include" | "access_log" | "error_log")
        {
            deny("的路径不能包含 ..")?;
        }
    }
    Ok(())
}

pub fn unified_diff(path: &str, old: &str, new: &str) -> String {
    similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITE: &str = "server {\n  listen 80;\n  listen 443 ssl http2; # tls\n  server_name example.com www.example.com;\n  # server_name commented.example;\n  location / { proxy_pass http://127.0.0.1:3000; }\n}\n";

    #[test]
    fn site_discovery_both_layouts() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("sites-available")).unwrap();
        std::fs::create_dir_all(r.join("sites-enabled")).unwrap();
        std::fs::create_dir_all(r.join("conf.d")).unwrap();
        std::fs::write(r.join("sites-available/shop"), SITE).unwrap();
        std::fs::write(r.join("sites-available/old"), "server { listen 8080; }").unwrap();
        std::os::unix::fs::symlink("../sites-available/shop", r.join("sites-enabled/shop"))
            .unwrap();
        std::fs::write(
            r.join("conf.d/api.conf"),
            "server { listen 81; server_name api; }",
        )
        .unwrap();
        std::fs::write(r.join("conf.d/gzip.conf"), "gzip on;").unwrap();
        std::fs::write(
            r.join("conf.d/legacy.conf.disabled"),
            "server { listen 82; }",
        )
        .unwrap();
        std::fs::write(r.join("nginx.conf"), "events {}").unwrap();
        std::fs::write(r.join("conf.d/site.key"), "secret").unwrap();

        let s = sites(r);
        let names: Vec<_> = s.iter().map(|x| (x.name.as_str(), x.enabled)).collect();
        assert_eq!(
            names,
            [
                ("api", true),
                ("legacy", false),
                ("old", false),
                ("shop", true)
            ]
        );
        let shop = s.iter().find(|x| x.name == "shop").unwrap();
        assert_eq!(shop.server_names, ["example.com", "www.example.com"]);
        assert!(shop.ssl);

        let edit = vec!["conf.d".to_string(), "sites-available".to_string()];
        let f = files(r, &edit);
        assert!(f.iter().any(|x| x.path == "nginx.conf" && !x.editable));
        assert!(f.iter().any(|x| x.path == "conf.d/api.conf" && x.editable));
        assert!(!f.iter().any(|x| x.path.ends_with(".key")));
        assert!(read_file(r, "conf.d/site.key", &edit).is_err());
        assert!(read_file(r, "sites-enabled/shop", &edit).is_err());
        let v = read_file(r, "sites-available/shop", &edit).unwrap();
        assert!(v.editable && v.content == SITE);
        assert!(check_path("nginx.conf", &edit, true).is_err());
        assert!(check_path("conf.d/x.txt", &edit, true).is_err());
        assert!(check_path("sites-available/newsite", &edit, true).is_ok());
    }

    #[test]
    fn directive_guard() {
        assert!(check_directives(SITE).is_ok());
        assert!(check_directives("access_log /var/log/nginx/a.log main;").is_ok());
        assert!(check_directives("error_log stderr;").is_ok());
        assert!(check_directives("# load_module x.so;\nserver {}").is_ok());
        for bad in [
            "load_module modules/evil.so;",
            "user root;",
            "server { access_log /etc/cron.d/x; }",
            "error_log /var/log/../../etc/x;",
            "include /root/secret.conf;",
            "location / { content_by_lua_block { os.execute('id') } }",
            "perl_modules /tmp;",
            "client_body_temp_path /etc/x;",
        ] {
            assert!(check_directives(bad).is_err(), "{bad}");
        }
        let d = unified_diff("conf.d/a.conf", "a\nb\n", "a\nc\n");
        assert!(d.contains("-b") && d.contains("+c") && d.contains("b/conf.d/a.conf"));
    }
}
