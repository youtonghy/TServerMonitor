//! nginx optimisation and hardening review (read-only): looks at the main config and the
//! enabled sites, plus the access statistics, and reports findings in the `nginx` and `perf`
//! categories. Nothing here changes a file; fixes are made in the nginx page or by hand.

use std::path::Path;

use crate::collect::access::AccessStats;
use crate::collect::security::Check;

/// Statements `name args` of a config text, comments removed.
fn directives(text: &str) -> Vec<(String, String)> {
    let t: String = text
        .lines()
        .map(|l| l.split_once('#').map_or(l, |(a, _)| a))
        .collect::<Vec<_>>()
        .join("\n");
    t.split([';', '{', '}'])
        .filter_map(|stmt| {
            let s = stmt.trim();
            let (k, v) = s.split_once(char::is_whitespace).unwrap_or((s, ""));
            (!k.is_empty()).then(|| {
                (
                    k.to_ascii_lowercase(),
                    v.split_whitespace().collect::<Vec<_>>().join(" "),
                )
            })
        })
        .collect()
}

fn check(
    key: &str,
    category: &'static str,
    severity: &'static str,
    title: &str,
    detail: &str,
    evidence: String,
) -> Check {
    Check {
        key: format!("{category}:{key}"),
        category,
        severity,
        title: title.into(),
        detail: detail.into(),
        evidence,
    }
}

/// `files` are (relative path, content) of nginx.conf, conf.d/*.conf and enabled sites.
pub fn lint(files: &[(String, String)], cpus: usize) -> Vec<Check> {
    let all: Vec<(String, String, String)> = files
        .iter()
        .flat_map(|(p, t)| {
            directives(t)
                .into_iter()
                .map(move |(k, v)| (p.clone(), k, v))
        })
        .collect();
    let find = |name: &'static str| all.iter().filter(move |(_, k, _)| k == name);
    let mut out = Vec::new();

    if !find("server_tokens").any(|(_, _, v)| v == "off") {
        out.push(check(
            "server-tokens",
            "nginx",
            "low",
            "nginx 在响应头和错误页中暴露版本号",
            "建议在 http 块加入 server_tokens off;，减少被按版本定向攻击的机会。",
            "server_tokens 未设置为 off".into(),
        ));
    }
    if !find("gzip").any(|(_, _, v)| v == "on") {
        out.push(check(
            "gzip",
            "nginx",
            "low",
            "未开启 gzip 压缩",
            "文本类响应（HTML/CSS/JS/JSON）未压缩会增加带宽与首屏时间。建议 gzip on; 并设置 gzip_types。",
            "没有 gzip on".into(),
        ));
    }
    if let Some((p, _, v)) = find("worker_processes").next()
        && v != "auto"
        && v.parse::<usize>().is_ok_and(|n| n < cpus)
    {
        out.push(check(
            "workers",
            "nginx",
            "info",
            "worker_processes 少于 CPU 核数",
            "设置为 auto 可以按 CPU 核数自动启动 worker。",
            format!("{p}: worker_processes {v}（本机 {cpus} 核）"),
        ));
    }
    for (p, _, v) in find("ssl_protocols") {
        let weak: Vec<&str> = v
            .split_whitespace()
            .filter(|x| matches!(*x, "SSLv3" | "TLSv1" | "TLSv1.1"))
            .collect();
        if !weak.is_empty() {
            out.push(check(
                "weak-tls",
                "nginx",
                "medium",
                "nginx 仍允许过时的 TLS 协议",
                "TLS 1.0/1.1 已被主流浏览器淘汰，建议 ssl_protocols TLSv1.2 TLSv1.3;",
                format!("{p}: ssl_protocols {v}"),
            ));
            break;
        }
    }
    let ssl_no_h2: Vec<String> = all
        .iter()
        .filter(|(_, k, v)| {
            k == "listen" && v.contains("ssl") && !v.contains("http2") && !v.contains("quic")
        })
        .map(|(p, _, v)| format!("{p}: listen {v}"))
        .collect();
    let http2_directive = find("http2").any(|(_, _, v)| v == "on");
    if !ssl_no_h2.is_empty() && !http2_directive {
        out.push(check(
            "http2",
            "nginx",
            "info",
            "HTTPS 站点未启用 HTTP/2",
            "HTTP/2 可复用连接、降低延迟。nginx 1.25.1+ 使用 http2 on;，更早版本在 listen 后加 http2。",
            ssl_no_h2.join("\n"),
        ));
    }
    if let Some((p, _, v)) = find("keepalive_timeout").next()
        && v.split_whitespace()
            .next()
            .and_then(|x| x.trim_end_matches('s').parse::<u32>().ok())
            .is_some_and(|n| n > 75)
    {
        out.push(check(
            "keepalive",
            "nginx",
            "info",
            "keepalive_timeout 偏长",
            "过长的空闲连接会占用 worker 连接数，一般 15–75 秒即可。",
            format!("{p}: keepalive_timeout {v}"),
        ));
    }
    let formats: Vec<&(String, String, String)> = find("log_format").collect();
    if !formats.iter().any(|(_, _, v)| v.contains("$request_time")) {
        out.push(check(
            "request-time",
            "nginx",
            "low",
            "访问日志没有记录请求耗时",
            "在 log_format 末尾追加 $request_time（或使用 JSON 格式并包含 request_time），面板即可统计延迟分位数和慢接口。",
            if formats.is_empty() { "使用默认 combined 格式".into() } else { format!("{} 个 log_format 均不含 $request_time", formats.len()) },
        ));
    }
    out
}

/// Slow endpoints and latency from the last hour of access statistics.
pub fn perf(stats: &AccessStats) -> Vec<Check> {
    let mut out = Vec::new();
    for p in stats
        .slow_paths
        .iter()
        .filter(|p| p.requests >= 20 && p.avg_ms.is_some_and(|a| a >= 1000.0))
        .take(5)
    {
        let avg = p.avg_ms.unwrap_or(0.0);
        let key: String = p
            .path
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '/')
            .take(80)
            .collect();
        out.push(check(
            &format!("slow:{key}"),
            "perf",
            if avg >= 3000.0 { "medium" } else { "low" },
            &format!("慢接口 {}：平均 {:.0} ms", p.path, avg),
            "最近一小时该接口平均响应超过 1 秒。可检查上游耗时、数据库慢查询，或为可缓存的响应加 proxy_cache。",
            format!("{} 次请求，平均 {avg:.0} ms，5xx {} 次", p.requests, p.s5xx),
        ));
    }
    if let Some(l) = &stats.latency
        && l.samples >= 200
        && l.p95_ms >= 2500.0
    {
        out.push(check(
            "p95",
            "perf",
            "medium",
            &format!("整体响应偏慢：P95 ≥ {:.0} ms", l.p95_ms),
            "最近一小时 5% 的请求超过该耗时，建议结合慢接口列表与主机负载排查。",
            format!(
                "P50 {:.0} ms / P95 {:.0} ms / P99 {:.0} ms（{} 个样本）",
                l.p50_ms, l.p95_ms, l.p99_ms, l.samples
            ),
        ));
    }
    out
}

/// Reads nginx.conf, conf.d/*.conf and enabled sites below `root` (best effort).
pub fn read_config(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut add = |rel: String| {
        if let Ok(t) = std::fs::read_to_string(root.join(&rel))
            && t.len() <= crate::ops::nginx::MAX_FILE
        {
            files.push((rel, t));
        }
    };
    add("nginx.conf".into());
    for dir in ["conf.d", "sites-enabled"] {
        let mut names: Vec<String> = std::fs::read_dir(root.join(dir))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| dir == "sites-enabled" || n.ends_with(".conf"))
            .collect();
        names.sort();
        for n in names {
            add(format!("{dir}/{n}"));
        }
    }
    files
}

/// Certificates of managed sites (from the helper's `nginx.sites`): expiring soon, expired,
/// or a failed automatic renewal. Category `cert`.
pub fn certs(sites: &[crate::ops::nginx::Site], now_ms: i64) -> Vec<Check> {
    use crate::ops::nginx_site::SslMode;
    let mut out = Vec::new();
    for s in sites.iter().filter(|s| s.enabled) {
        let Some(c) = &s.cert else { continue };
        if c.mode == SslMode::None {
            continue;
        }
        let auto = c.mode == SslMode::Acme;
        if let Some(na) = c.not_after {
            let days = (na - now_ms).div_euclid(86_400_000);
            let date = chrono::DateTime::from_timestamp_millis(na)
                .map(|t| t.format("%Y-%m-%d").to_string())
                .unwrap_or_default();
            let (sev, title) = if days < 0 {
                ("critical", format!("站点 {} 的证书已过期", s.name))
            } else if days < 7 {
                (
                    "high",
                    format!("站点 {} 的证书将在 {days} 天后过期", s.name),
                )
            } else if days < if auto { 20 } else { 21 } {
                (
                    "medium",
                    format!("站点 {} 的证书将在 {days} 天后过期", s.name),
                )
            } else {
                ("", String::new())
            };
            if !sev.is_empty() {
                let detail = if auto {
                    "自动续期没有及时完成。请在 nginx 页面查看最近一次申请的错误，确认域名仍解析到本机且 80 端口可访问，然后手动点“申请证书”。"
                } else {
                    "请在到期前上传新证书，或改为自动申请。"
                };
                out.push(check(
                    &format!("expiry:{}", s.name),
                    "cert",
                    sev,
                    &title,
                    detail,
                    format!("{} 到期：{date}", s.server_names.join(" ")),
                ));
            }
        }
        if auto && let Some(err) = &c.last_error {
            out.push(check(
                &format!("renew-failed:{}", s.name),
                "cert",
                "medium",
                &format!("站点 {} 的证书申请失败", s.name),
                "最近一次自动申请或续期没有成功；助手会在 6 小时后重试。",
                err.chars().take(500).collect(),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_flags_and_passes() {
        let weak = vec![(
            "nginx.conf".to_string(),
            "worker_processes 1;\nhttp {\n  keepalive_timeout 300;\n  # gzip on;\n  ssl_protocols TLSv1 TLSv1.2;\n  server { listen 443 ssl; }\n}\n".to_string(),
        )];
        let keys: Vec<String> = lint(&weak, 4).into_iter().map(|c| c.key).collect();
        for k in [
            "nginx:server-tokens",
            "nginx:gzip",
            "nginx:workers",
            "nginx:weak-tls",
            "nginx:http2",
            "nginx:keepalive",
            "nginx:request-time",
        ] {
            assert!(keys.contains(&k.to_string()), "{k} missing in {keys:?}");
        }
        let good = vec![(
            "nginx.conf".to_string(),
            "worker_processes auto;\nhttp {\n server_tokens off;\n gzip on;\n keepalive_timeout 30;\n log_format main '$remote_addr \"$request\" $status $request_time';\n ssl_protocols TLSv1.2 TLSv1.3;\n server { listen 443 ssl; http2 on; }\n}\n".to_string(),
        )];
        assert!(
            lint(&good, 4).is_empty(),
            "{:?}",
            lint(&good, 4).iter().map(|c| &c.key).collect::<Vec<_>>()
        );
    }

    #[test]
    fn perf_findings_from_access_stats() {
        let a = crate::collect::access::Access::default();
        let t = 1_700_000_000_000;
        for _ in 0..30 {
            a.record(
                r#"10.0.0.1 - - [x] "GET /report HTTP/1.1" 200 1 "-" "-" 3.2"#,
                t,
            );
        }
        let c = perf(&a.stats(60, t, 20, true));
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severity, "medium");
        assert!(c[0].title.contains("/report"));
    }

    #[test]
    fn certificate_findings() {
        use crate::ops::nginx::{Layout, Site};
        use crate::ops::nginx_site::{CertInfo, SslMode};
        let now = 1_000 * 86_400_000;
        let site = |name: &str, mode, days: Option<i64>, err: Option<&str>| Site {
            name: name.into(),
            file: format!("conf.d/{name}.conf"),
            enabled: true,
            layout: Layout::ConfD,
            server_names: vec![format!("{name}.example.com")],
            listen: vec![],
            ssl: true,
            managed: true,
            kind: None,
            drifted: false,
            cert: Some(CertInfo {
                mode,
                not_after: days.map(|d| now + d * 86_400_000),
                last_error: err.map(str::to_string),
                ..Default::default()
            }),
        };
        let c = certs(
            &[
                site("ok", SslMode::Acme, Some(60), None),
                site("soon", SslMode::Upload, Some(10), None),
                site("gone", SslMode::Acme, Some(-1), Some("timeout")),
                site("new", SslMode::Acme, None, Some("dns")),
            ],
            now,
        );
        let keys: Vec<(&str, &str)> = c.iter().map(|c| (c.key.as_str(), c.severity)).collect();
        assert_eq!(
            keys,
            [
                ("cert:expiry:soon", "medium"),
                ("cert:expiry:gone", "critical"),
                ("cert:renew-failed:gone", "medium"),
                ("cert:renew-failed:new", "medium"),
            ]
        );
    }
}
