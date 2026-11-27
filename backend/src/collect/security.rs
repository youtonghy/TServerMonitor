//! Host security and baseline checks (Linux). Reads procfs, sysctl values, sshd config and
//! auth logs; package checks only run read-only simulations (`apt-get -s`, `dnf updateinfo`).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::model::{PortInfo, now_ms};
use crate::state::Shared;
use crate::store::{self, NewFinding};

#[derive(Debug, Clone)]
pub struct Check {
    pub key: String,
    pub category: &'static str,
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
    pub evidence: String,
}

// ---------------------------------------------------------------- listening ports

fn parse_hex_addr(s: &str, v6: bool) -> Option<(String, u16)> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if v6 {
        if addr.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in bytes.chunks_mut(4).enumerate() {
            let word = u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16).ok()?;
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        std::net::Ipv6Addr::from(bytes).to_string()
    } else {
        let n = u32::from_str_radix(addr, 16).ok()?;
        std::net::Ipv4Addr::from(n.to_le_bytes()).to_string()
    };
    Some((ip, port))
}

fn is_loopback(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>()
        .map(|a| a.is_loopback())
        .unwrap_or(false)
        || addr.starts_with("127.")
        || addr == "::ffff:127.0.0.1"
}

/// Parses /proc/net/{tcp,tcp6,udp,udp6} content into listening sockets.
pub fn parse_proc_net(content: &str, proto: &'static str, v6: bool) -> Vec<(String, u16, u64)> {
    content
        .lines()
        .skip(1)
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            if cols.len() < 10 {
                return None;
            }
            // TCP LISTEN = 0A; UDP "listening" = unconnected (07)
            let listening = if proto == "tcp" {
                cols[3] == "0A"
            } else {
                cols[3] == "07"
            };
            if !listening {
                return None;
            }
            let (ip, port) = parse_hex_addr(cols[1], v6)?;
            Some((ip, port, cols[9].parse().unwrap_or(0)))
        })
        .collect()
}

fn socket_owners() -> HashMap<u64, String> {
    // best effort: needs permission to read other users' /proc/<pid>/fd
    let mut map = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return map;
    };
    for p in procs.flatten() {
        let pid = p.file_name();
        if !pid.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let comm = std::fs::read_to_string(p.path().join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                if let Some(inode) = t
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse().ok())
                {
                    map.insert(inode, comm.clone());
                }
            }
        }
    }
    map
}

pub fn listening_ports() -> Vec<PortInfo> {
    let owners = socket_owners();
    let mut out = Vec::new();
    for (file, proto, v6) in [
        ("/proc/net/tcp", "tcp", false),
        ("/proc/net/tcp6", "tcp", true),
        ("/proc/net/udp", "udp", false),
        ("/proc/net/udp6", "udp", true),
    ] {
        let Ok(content) = std::fs::read_to_string(file) else {
            continue;
        };
        for (addr, port, inode) in parse_proc_net(&content, proto, v6) {
            out.push(PortInfo {
                proto,
                exposed: !is_loopback(&addr),
                addr,
                port,
                process: owners.get(&inode).cloned(),
            });
        }
    }
    out.sort_by(|a, b| (a.proto, a.port, &a.addr).cmp(&(b.proto, b.port, &b.addr)));
    out.dedup_by(|a, b| a.proto == b.proto && a.port == b.port && a.addr == b.addr);
    out
}

/// Ports that are commonly dangerous when reachable from outside.
const RISKY_PORTS: &[(u16, &str)] = &[
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (11211, "Memcached"),
    (27017, "MongoDB"),
    (9200, "Elasticsearch"),
    (2375, "Docker API (未加密)"),
    (2376, "Docker API"),
    (5984, "CouchDB"),
    (9000, "PHP-FPM / 管理端口"),
    (15672, "RabbitMQ 管理台"),
    (8086, "InfluxDB"),
];

pub fn port_checks(ports: &[PortInfo]) -> Vec<Check> {
    let mut out = Vec::new();
    for p in ports.iter().filter(|p| p.exposed && p.proto == "tcp") {
        if let Some((_, svc)) = RISKY_PORTS.iter().find(|(port, _)| *port == p.port) {
            out.push(Check {
                key: format!("port:{}:{}", p.addr, p.port),
                category: "port",
                severity: if matches!(p.port, 2375 | 6379 | 11211 | 27017 | 9200) { "critical" } else { "high" },
                title: format!("{svc} 端口 {} 监听在非回环地址", p.port),
                detail: format!("{svc} 在 {}:{} 上对外监听。若无防火墙限制，可能被外网直接访问。建议改为监听 127.0.0.1 或内网地址，并在防火墙中限制来源。", p.addr, p.port),
                evidence: format!("{} {}:{} {}", p.proto, p.addr, p.port, p.process.as_deref().unwrap_or("")),
            });
        }
    }
    out
}

// ---------------------------------------------------------------- sysctl / sshd

const SYSCTL_EXPECT: &[(&str, &str, &str, &str)] = &[
    // (key, expected, severity, explanation)
    (
        "net.ipv4.tcp_syncookies",
        "1",
        "medium",
        "关闭 SYN cookies 会降低抵御 SYN Flood 的能力",
    ),
    (
        "kernel.randomize_va_space",
        "2",
        "medium",
        "地址空间随机化未完全开启，降低漏洞利用难度",
    ),
    (
        "net.ipv4.conf.all.accept_redirects",
        "0",
        "low",
        "接受 ICMP 重定向可能被用于中间人攻击",
    ),
    (
        "net.ipv4.conf.all.send_redirects",
        "0",
        "low",
        "非路由主机不应发送 ICMP 重定向",
    ),
    (
        "net.ipv4.conf.all.accept_source_route",
        "0",
        "low",
        "源路由可被用于绕过访问控制",
    ),
    (
        "fs.protected_symlinks",
        "1",
        "low",
        "未开启符号链接保护，存在 /tmp 竞争攻击风险",
    ),
    ("fs.protected_hardlinks", "1", "low", "未开启硬链接保护"),
    (
        "kernel.dmesg_restrict",
        "1",
        "info",
        "普通用户可读取内核日志",
    ),
];

pub fn read_sysctl(root: &Path, key: &str) -> Option<String> {
    let p = root.join(key.replace('.', "/"));
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn sysctl_checks(root: &Path) -> Vec<Check> {
    let mut out = Vec::new();
    for (key, expected, severity, why) in SYSCTL_EXPECT {
        if let Some(v) = read_sysctl(root, key)
            && v != *expected
        {
            out.push(Check {
                key: format!("sysctl:{key}"),
                category: "kernel",
                severity,
                title: format!("内核参数 {key} = {v}（建议 {expected}）"),
                detail: (*why).to_string(),
                evidence: format!("/proc/sys/{} = {v}", key.replace('.', "/")),
            });
        }
    }
    if let Some(v) = read_sysctl(root, "net.core.somaxconn").and_then(|v| v.parse::<u32>().ok())
        && v < 1024
    {
        out.push(Check {
            key: "sysctl:net.core.somaxconn".into(),
            category: "network",
            severity: "info",
            title: format!("net.core.somaxconn 较小（{v}）"),
            detail: "高并发 Web 服务建议调大监听队列（如 4096），避免突发流量时连接被丢弃。".into(),
            evidence: format!("net.core.somaxconn = {v}"),
        });
    }
    if let Some(v) = read_sysctl(root, "vm.swappiness").and_then(|v| v.parse::<u32>().ok())
        && v > 60
    {
        out.push(Check {
            key: "sysctl:vm.swappiness".into(),
            category: "kernel",
            severity: "info",
            title: format!("vm.swappiness 偏高（{v}）"),
            detail: "数据库与 PHP-FPM 等延迟敏感服务通常建议 swappiness 设为 10 左右。".into(),
            evidence: format!("vm.swappiness = {v}"),
        });
    }
    out
}

/// Effective sshd settings: last occurrence outside Match blocks wins in our simplified view.
pub fn sshd_checks(config: &str) -> Vec<Check> {
    let mut settings: HashMap<String, String> = HashMap::new();
    for line in config.lines() {
        let line = line.trim();
        if line.to_ascii_lowercase().starts_with("match ") {
            break;
        }
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        if let (Some(k), Some(v)) = (it.next(), it.next()) {
            // sshd uses the first value it sees
            settings
                .entry(k.to_ascii_lowercase())
                .or_insert_with(|| v.trim().to_ascii_lowercase());
        }
    }
    let mut out = Vec::new();
    if settings.get("permitrootlogin").map(String::as_str) == Some("yes") {
        out.push(Check {
            key: "sshd:permitrootlogin".into(),
            category: "config",
            severity: "high",
            title: "SSH 允许 root 直接登录".into(),
            detail: "建议设置 PermitRootLogin no 或 prohibit-password，并使用普通用户 + sudo。"
                .into(),
            evidence: "PermitRootLogin yes".into(),
        });
    }
    if settings.get("passwordauthentication").map(String::as_str) != Some("no") {
        out.push(Check {
            key: "sshd:passwordauthentication".into(),
            category: "config",
            severity: "medium",
            title: "SSH 允许密码登录".into(),
            detail: "密码登录易遭暴力破解，建议改用密钥登录并设置 PasswordAuthentication no。"
                .into(),
            evidence: format!(
                "PasswordAuthentication {}",
                settings
                    .get("passwordauthentication")
                    .map(String::as_str)
                    .unwrap_or("(默认 yes)")
            ),
        });
    }
    out
}

// ---------------------------------------------------------------- auth log

/// sshd lines from the journal (hosts without an auth log file), drained every minute.
static JOURNAL_AUTH: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn push_auth_line(line: String) {
    let mut q = JOURNAL_AUTH.lock().unwrap_or_else(|e| e.into_inner());
    if q.len() < 20_000 {
        q.push(line);
    }
}

#[derive(Default)]
pub struct AuthWatch {
    tail: Option<crate::collect::logs::FileTail>,
    failures: HashMap<String, VecDeque<i64>>,
    root_logins: VecDeque<(i64, String)>,
}

static FAILED_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?:Failed password|Invalid user|authentication failure|Connection closed by authenticating user).*?(?:from|rhost=)\s*([0-9a-fA-F:.]+)").unwrap()
});
static ROOT_OK_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"Accepted (\w+) for root from ([0-9a-fA-F:.]+)").unwrap()
});

impl AuthWatch {
    pub fn feed(&mut self, line: &str, now: i64) {
        if let Some(c) = FAILED_RE.captures(line) {
            self.failures
                .entry(c[1].to_string())
                .or_default()
                .push_back(now);
        } else if let Some(c) = ROOT_OK_RE.captures(line) {
            self.root_logins
                .push_back((now, format!("{} from {}", &c[1], &c[2])));
        }
    }

    pub fn checks(&mut self, now: i64, threshold: u32) -> Vec<Check> {
        let window = 3_600_000;
        let mut out = Vec::new();
        self.failures.retain(|_, q| {
            while q.front().is_some_and(|t| now - t > window) {
                q.pop_front();
            }
            !q.is_empty()
        });
        let mut top: Vec<(&String, usize)> = self
            .failures
            .iter()
            .map(|(ip, q)| (ip, q.len()))
            .filter(|(_, n)| *n as u32 >= threshold)
            .collect();
        top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        for (ip, n) in top.into_iter().take(20) {
            out.push(Check {
                key: format!("login:bruteforce:{ip}"),
                category: "login",
                severity: if n as u32 >= threshold * 5 {
                    "high"
                } else {
                    "medium"
                },
                title: format!("来自 {ip} 的登录失败 {n} 次/小时"),
                detail: "疑似 SSH 暴力破解。建议启用 fail2ban、关闭密码登录或限制 SSH 来源地址。"
                    .into(),
                evidence: format!("{n} failed attempts in the last hour"),
            });
        }
        while self
            .root_logins
            .front()
            .is_some_and(|(t, _)| now - t > 24 * window)
        {
            self.root_logins.pop_front();
        }
        if let Some((_, how)) = self.root_logins.back() {
            out.push(Check {
                key: "login:root".into(),
                category: "login",
                severity: "medium",
                title: format!("24 小时内有 root 直接登录（{how}）"),
                detail: "请确认该登录是否为预期操作。".into(),
                evidence: format!("{} root logins in 24h", self.root_logins.len()),
            });
        }
        out
    }
}

fn auth_log_path(cfg: Option<&PathBuf>) -> Option<PathBuf> {
    if let Some(p) = cfg {
        return Some(p.clone());
    }
    ["/var/log/auth.log", "/var/log/secure"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

// ---------------------------------------------------------------- pending updates

async fn run_readonly(cmd: &str, args: &[&str]) -> Option<String> {
    let fut = tokio::process::Command::new(cmd)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(Duration::from_secs(120), fut).await {
        Ok(Ok(out)) => Some(String::from_utf8_lossy(&out.stdout).to_string()),
        _ => None,
    }
}

pub fn count_apt_security(sim: &str) -> (usize, usize) {
    let inst: Vec<&str> = sim.lines().filter(|l| l.starts_with("Inst ")).collect();
    let sec = inst
        .iter()
        .filter(|l| l.to_ascii_lowercase().contains("security"))
        .count();
    (inst.len(), sec)
}

async fn update_checks() -> Option<Check> {
    if Path::new("/usr/bin/apt-get").exists() {
        // -s simulates: nothing is downloaded or installed; package lists are not refreshed
        let out = run_readonly("apt-get", &["-s", "-o", "Debug::NoLocking=1", "upgrade"]).await?;
        let (total, sec) = count_apt_security(&out);
        return (total > 0).then(|| Check {
            key: "updates:pending".into(),
            category: "update",
            severity: if sec > 0 { "high" } else { "low" },
            title: format!("有 {total} 个待更新软件包，其中安全更新 {sec} 个"),
            detail: "结果基于本机现有的软件包索引（本系统不会刷新索引或安装任何包）。建议在维护窗口执行升级。".into(),
            evidence: format!("apt-get -s upgrade: {total} upgradable, {sec} security"),
        });
    }
    if Path::new("/usr/bin/dnf").exists() {
        let out = run_readonly(
            "dnf",
            &["-q", "--cacheonly", "updateinfo", "list", "--security"],
        )
        .await?;
        let n = out.lines().filter(|l| !l.trim().is_empty()).count();
        return (n > 0).then(|| Check {
            key: "updates:pending".into(),
            category: "update",
            severity: "high",
            title: format!("有 {n} 条待安装的安全更新"),
            detail: "结果基于本机缓存（--cacheonly）。建议在维护窗口执行 dnf upgrade --security。"
                .into(),
            evidence: format!("dnf updateinfo list --security: {n} entries"),
        });
    }
    None
}

// ---------------------------------------------------------------- runner

async fn apply(state: &Shared, category: &str, checks: &[Check]) {
    let mut keep = Vec::new();
    for c in checks {
        keep.push(c.key.clone());
        let f = NewFinding {
            key: &c.key,
            category: c.category,
            severity: c.severity,
            title: &c.title,
            detail: &c.detail,
            evidence: &c.evidence,
        };
        match store::upsert_finding(&state.db, &f).await {
            Ok(true) => crate::rules::on_new_finding(state, c).await,
            Ok(false) => {}
            Err(e) => tracing::warn!("storing finding: {e:#}"),
        }
    }
    if let Err(e) = store::resolve_findings_except(&state.db, category, &keep).await {
        tracing::warn!("resolving findings: {e:#}");
    }
}

pub fn spawn(state: &Shared) {
    if !state.cfg.security.enabled {
        state.set_collector("security", false, Some("已在配置中关闭".into()));
        return;
    }
    if !cfg!(target_os = "linux") {
        state.set_collector(
            "security",
            false,
            Some("安全体检仅支持 Linux，当前平台已跳过".into()),
        );
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        let mut auth = AuthWatch::default();
        let auth_path = auth_log_path(state.cfg.security.auth_log.as_ref());
        auth.tail = auth_path.clone().map(crate::collect::logs::FileTail::new);
        let mut last_full = 0i64;
        loop {
            // auth log is cheap: read it every minute
            if let Some(mut t) = auth.tail.take() {
                let (t2, lines) = tokio::task::spawn_blocking(move || {
                    let r = t.poll();
                    (t, r)
                })
                .await
                .expect("auth tail task");
                auth.tail = Some(t2);
                let now = now_ms();
                if let Ok(lines) = lines {
                    for l in lines {
                        auth.feed(&l, now);
                    }
                }
            }
            let now = now_ms();
            if auth.tail.is_none() {
                let lines =
                    std::mem::take(&mut *JOURNAL_AUTH.lock().unwrap_or_else(|e| e.into_inner()));
                for l in lines {
                    auth.feed(&l, now);
                }
            }
            let login = auth.checks(now, state.cfg.security.failed_login_threshold);
            apply(&state, "login", &login).await;

            if now - last_full >= state.cfg.security.interval_secs as i64 * 1000
                && !state.is_yielding()
            {
                last_full = now;
                let ports = tokio::task::spawn_blocking(listening_ports)
                    .await
                    .unwrap_or_default();
                apply(&state, "port", &port_checks(&ports)).await;
                state.write().ports = ports;

                let sys = sysctl_checks(Path::new("/proc/sys"));
                let (kernel, network): (Vec<Check>, Vec<Check>) =
                    sys.into_iter().partition(|c| c.category == "kernel");
                apply(&state, "kernel", &kernel).await;
                apply(&state, "network", &network).await;

                let mut cfg_checks = std::fs::read_to_string("/etc/ssh/sshd_config")
                    .map(|c| sshd_checks(&c))
                    .unwrap_or_default();
                if Path::new("/var/run/reboot-required").exists() {
                    cfg_checks.push(Check {
                        key: "config:reboot-required".into(),
                        category: "config",
                        severity: "medium",
                        title: "系统更新后需要重启".into(),
                        detail: "已安装的内核或核心库更新需要重启才能生效。".into(),
                        evidence: "/var/run/reboot-required exists".into(),
                    });
                }
                apply(&state, "config", &cfg_checks).await;

                let root = state.cfg.ops.nginx_root.clone();
                if root.join("nginx.conf").is_file() {
                    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
                    let files = crate::collect::nginx_lint::read_config(&root);
                    apply(
                        &state,
                        "nginx",
                        &crate::collect::nginx_lint::lint(&files, cpus),
                    )
                    .await;
                }
                // certificates of managed sites (only the helper can see them)
                if let Ok(v) = crate::ops::read(&state, "nginx.sites", serde_json::json!({})).await
                {
                    let sites: Vec<crate::ops::nginx::Site> =
                        serde_json::from_value(v["data"]["sites"].clone()).unwrap_or_default();
                    apply(
                        &state,
                        "cert",
                        &crate::collect::nginx_lint::certs(&sites, now_ms()),
                    )
                    .await;
                }
                if state
                    .cfg
                    .logs
                    .iter()
                    .any(|l| l.kind == crate::config::LogKind::NginxAccess)
                {
                    let stats = crate::collect::pipeline()
                        .access
                        .stats(60, now_ms(), 20, true);
                    apply(&state, "perf", &crate::collect::nginx_lint::perf(&stats)).await;
                }

                if state.cfg.security.check_updates {
                    let upd: Vec<Check> = update_checks().await.into_iter().collect();
                    apply(&state, "update", &upd).await;
                }
                let detail = if auth_path.is_none() && !state.cfg.journal.enabled {
                    Some("未找到 auth 日志，登录审计已跳过".into())
                } else if auth_path.is_none() {
                    Some("未找到 auth 日志，登录审计改用 systemd journal".into())
                } else {
                    None
                };
                state.set_collector("security", true, detail);
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_tcp() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 12345 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1\n   2: 0100007F:1F91 0100007F:9999 01 00000000:00000000 00:00000000 00000000     0        0 333 1\n";
        let ports = parse_proc_net(content, "tcp", false);
        assert_eq!(
            ports,
            vec![
                ("0.0.0.0".to_string(), 3306, 12345),
                ("127.0.0.1".to_string(), 8080, 222)
            ]
        );
        let infos: Vec<PortInfo> = ports
            .into_iter()
            .map(|(addr, port, _)| PortInfo {
                proto: "tcp",
                exposed: !is_loopback(&addr),
                addr,
                port,
                process: None,
            })
            .collect();
        let checks = port_checks(&infos);
        assert_eq!(checks.len(), 1);
        assert!(checks[0].title.contains("MySQL"));
    }

    #[test]
    fn parses_ipv6_any() {
        let content = "hdr\n 0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0 0 0 0 0 0 1 0\n";
        let ports = parse_proc_net(content, "tcp", true);
        assert_eq!(ports[0].0, "::");
        assert_eq!(ports[0].1, 22);
    }

    #[test]
    fn sysctl_flags_bad_values() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("net/ipv4");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("tcp_syncookies"), "0\n").unwrap();
        let checks = sysctl_checks(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].key, "sysctl:net.ipv4.tcp_syncookies");
    }

    #[test]
    fn sshd_root_and_password() {
        let c = sshd_checks("PermitRootLogin yes\n#PasswordAuthentication no\n");
        assert_eq!(c.len(), 2);
        let c = sshd_checks(
            "PermitRootLogin no\nPasswordAuthentication no\nMatch User x\nPermitRootLogin yes\n",
        );
        assert!(c.is_empty());
    }

    #[test]
    fn auth_bruteforce_detection() {
        let mut w = AuthWatch::default();
        for _ in 0..25 {
            w.feed("May  1 10:00:00 h sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2", 1000);
        }
        let c = w.checks(2000, 20);
        assert_eq!(c.len(), 1);
        assert!(c[0].title.contains("203.0.113.9"));
    }

    #[test]
    fn apt_simulation_counts() {
        let sim = "Inst libssl3 [3.0.2] (3.0.2-0ubuntu1.15 Ubuntu:22.04/jammy-security [amd64])\nInst vim [2:8.2] (2:8.2.1 Ubuntu:22.04/jammy-updates [amd64])\nConf libssl3\n";
        assert_eq!(count_apt_security(sim), (2, 1));
    }
}
