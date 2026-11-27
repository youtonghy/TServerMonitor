//! Real-time access analysis for `nginx_access` sources: per-minute request counts, status
//! classes, bytes, latency histogram, busiest and slowest paths, client addresses (with 4xx and
//! scanner and injection hits), virtual hosts and user-agent classes.
//!
//! Accepted line formats:
//! * nginx `combined`, optionally followed by `$request_time` (or `rt=` / `request_time=`) and
//!   `host=` / `vhost=` tokens;
//! * JSON access logs (`escape=json`) with the usual field names (`remote_addr`, `request` or
//!   `request_method` + `request_uri`, `status`, `body_bytes_sent`, `request_time`,
//!   `http_user_agent`, `host`).
//!
//! The last hour is kept in memory with bounded maps; closed minutes are handed to the flusher
//! ([`Access::drain_closed`]) and persisted, so history survives restarts.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde::{Deserialize, Serialize};

const KEEP_MINUTES: usize = 60;
/// Distinct paths / addresses tracked per minute; the rest is counted under "(other)".
const MAP_CAP: usize = 2000;
const OTHER: &str = "(other)";
/// Upper bounds (ms) of the latency buckets; the last bucket is open-ended.
pub const LATENCY_BOUNDS: [f64; 11] = [
    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0,
];
const BUCKETS: usize = LATENCY_BOUNDS.len() + 1;

/// `ip - user [time] "METHOD path PROTO" status bytes ["referer" "ua"] [extra...]`
static LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^(\S+) \S+ \S+ \[[^\]]*\] "([A-Z]{3,10}) ([^ "]+)[^"]*" (\d{3}) (\d+|-)(?: "[^"]*" "([^"]*)")?(.*)$"#,
    )
    .expect("static regex")
});

/// Paths typical of vulnerability scanners and bots probing for leaked files.
static SCAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(/\.env|/\.git/|/\.aws/|/\.ssh/|wp-login\.php|/wp-admin|xmlrpc\.php|phpmyadmin|/pma/|/cgi-bin/|\.\./|/etc/passwd|/actuator|/vendor/phpunit|/boaform|/hnap1|/server-status|/\.ds_store|/config\.json|/console/|/solr/|/manager/html|\.(?:bak|sql|swp)$)",
    )
    .expect("static regex")
});

/// Injection payloads (SQL, script, command, traversal) in the URL-decoded path and query.
static INJECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)",
        // SQL
        r"\bunion\b[\s/*+()]+(?:all[\s/*+]+|distinct[\s/*+]+)?select\b",
        r"|\binformation_schema\b|@@version\b|/\*!\d*",
        r"|\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml|load_file)\s*\(",
        r"|\bwaitfor\s+delay\b|\binto\s+(?:out|dump)file\b",
        r"|'\s*(?:or|and)\s+(?:'[^']*'\s*=\s*'|\d+\s*=\s*\d+|true\b)",
        r"|\b(?:or|and)\s+\d+\s*=\s*\d+\b",
        r"|'\s*(?:--|#|/\*)|;\s*(?:drop|delete|insert|update|select|shutdown)\s",
        // script
        r"|<script\b|javascript:|\bon(?:error|load|mouseover|focus)\s*=",
        // command, JNDI, traversal
        r"|\$\{jndi:|\$\((?:id|whoami|curl|wget|cat)\b|`(?:id|whoami)`",
        r"|[;|]\s*(?:cat|wget|curl|bash|sh|nc|id|whoami)(?:\s|$)",
        r"|(?:\.\./){2,}|/etc/(?:passwd|shadow)\b",
    ))
    .expect("static regex")
});

/// Percent-decodes twice (payloads are often double-encoded) and turns `+` into a space.
fn decode_uri(raw: &str) -> String {
    fn once(s: &str) -> String {
        let hex = |c: u8| (c as char).to_digit(16);
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%'
                && let (Some(h), Some(l)) = (
                    b.get(i + 1).and_then(|&c| hex(c)),
                    b.get(i + 2).and_then(|&c| hex(c)),
                )
            {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    once(&once(raw))
}

fn is_injection(raw: &str) -> bool {
    INJECT.is_match(&decode_uri(raw))
}

#[derive(Debug, PartialEq)]
pub struct Request {
    pub ip: String,
    pub method: String,
    /// Query string removed, ids templated.
    pub path: String,
    pub status: u16,
    pub bytes: u64,
    /// Request time in milliseconds, when the log format has it.
    pub rt_ms: Option<f64>,
    pub ua: Option<String>,
    pub host: Option<String>,
    /// The raw path looks like a scanner probe.
    pub scan: bool,
    /// The path or query carries an injection payload (SQL, script, command, traversal).
    pub inject: bool,
}

fn clean_path(raw: &str) -> (String, bool) {
    let p = raw.split(['?', '#']).next().unwrap_or(raw);
    (
        crate::preprocess::template(&crate::preprocess::redact(p)),
        SCAN.is_match(p),
    )
}

/// `0.123` (seconds) -> 123 ms; `-` and garbage -> None.
fn seconds(s: &str) -> Option<f64> {
    let v: f64 = s.trim_matches('"').parse().ok()?;
    (v.is_finite() && (0.0..86_400.0).contains(&v)).then_some(v * 1000.0)
}

fn parse_extra(extra: &str) -> (Option<f64>, Option<String>) {
    let mut rt = None;
    let mut host = None;
    for tok in extra.split_whitespace() {
        let tok = tok.trim_matches('"');
        if let Some(v) = tok
            .strip_prefix("rt=")
            .or_else(|| tok.strip_prefix("request_time="))
        {
            rt = rt.or_else(|| seconds(v));
        } else if let Some(v) = tok
            .strip_prefix("host=")
            .or_else(|| tok.strip_prefix("vhost="))
        {
            if !v.is_empty() && v != "-" {
                host = Some(v.to_ascii_lowercase());
            }
        } else if rt.is_none() && tok.contains('.') {
            rt = seconds(tok);
        }
    }
    (rt, host)
}

#[derive(Deserialize)]
struct JsonLine {
    #[serde(alias = "remote_addr", alias = "client", alias = "ip")]
    remote_addr: Option<String>,
    request: Option<String>,
    request_method: Option<String>,
    #[serde(alias = "uri")]
    request_uri: Option<String>,
    status: Option<serde_json::Value>,
    #[serde(alias = "bytes_sent")]
    body_bytes_sent: Option<serde_json::Value>,
    request_time: Option<serde_json::Value>,
    http_user_agent: Option<String>,
    #[serde(alias = "server_name", alias = "http_host")]
    host: Option<String>,
}

fn num(v: &Option<serde_json::Value>) -> Option<f64> {
    match v.as_ref()? {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn parse_json(line: &str) -> Option<Request> {
    let j: JsonLine = serde_json::from_str(line).ok()?;
    let (method, raw) = match (&j.request_method, &j.request_uri, &j.request) {
        (Some(m), Some(u), _) => (m.clone(), u.clone()),
        (_, _, Some(r)) => {
            let mut w = r.split_whitespace();
            (w.next()?.to_string(), w.next()?.to_string())
        }
        _ => return None,
    };
    let (path, scan) = clean_path(&raw);
    let inject = is_injection(&raw);
    Some(Request {
        ip: j.remote_addr?,
        method,
        path,
        status: num(&j.status)? as u16,
        bytes: num(&j.body_bytes_sent).unwrap_or(0.0) as u64,
        rt_ms: num(&j.request_time).and_then(|s| seconds(&s.to_string())),
        ua: j.http_user_agent.filter(|u| !u.is_empty() && u != "-"),
        host: j
            .host
            .filter(|h| !h.is_empty() && h != "-")
            .map(|h| h.to_ascii_lowercase()),
        scan,
        inject,
    })
}

/// Parses one access log line (combined, combined + extras, or JSON).
pub fn parse(line: &str) -> Option<Request> {
    let t = line.trim_start();
    if t.starts_with('{') {
        return parse_json(t);
    }
    let c = LINE.captures(line)?;
    let raw = c.get(3)?.as_str();
    let (path, scan) = clean_path(raw);
    let (rt_ms, host) = c.get(7).map_or((None, None), |m| parse_extra(m.as_str()));
    Some(Request {
        ip: c.get(1)?.as_str().to_string(),
        method: c.get(2)?.as_str().to_string(),
        path,
        status: c.get(4)?.as_str().parse().ok()?,
        bytes: c.get(5)?.as_str().parse().unwrap_or(0),
        rt_ms,
        ua: c
            .get(6)
            .map(|m| m.as_str().to_string())
            .filter(|u| !u.is_empty() && u != "-"),
        host,
        scan,
        inject: is_injection(raw),
    })
}

/// browser | bot | tool | scanner | empty | other
pub fn ua_class(ua: Option<&str>) -> &'static str {
    let Some(u) = ua else { return "empty" };
    let l = u.to_ascii_lowercase();
    if [
        "nikto",
        "sqlmap",
        "nmap",
        "zgrab",
        "masscan",
        "nuclei",
        "dirbuster",
        "gobuster",
        "wpscan",
        "censys",
    ]
    .iter()
    .any(|x| l.contains(x))
    {
        "scanner"
    } else if [
        "bot",
        "crawler",
        "spider",
        "slurp",
        "bingpreview",
        "facebookexternalhit",
    ]
    .iter()
    .any(|x| l.contains(x))
    {
        "bot"
    } else if [
        "curl",
        "wget",
        "python",
        "go-http",
        "java/",
        "okhttp",
        "libwww",
        "httpclient",
        "postman",
        "axios",
        "node-fetch",
    ]
    .iter()
    .any(|x| l.contains(x))
    {
        "tool"
    } else if l.starts_with("mozilla/") {
        "browser"
    } else {
        "other"
    }
}

fn bucket(ms: f64) -> usize {
    LATENCY_BOUNDS
        .iter()
        .position(|b| ms <= *b)
        .unwrap_or(LATENCY_BOUNDS.len())
}

/// Upper bound of the bucket holding the `q` quantile (ms); the open bucket reports 2x the
/// last bound.
pub fn quantile(hist: &[u64], q: f64) -> Option<f64> {
    let total: u64 = hist.iter().sum();
    if total == 0 {
        return None;
    }
    let target = (total as f64 * q).ceil().max(1.0) as u64;
    let mut acc = 0;
    for (i, n) in hist.iter().enumerate() {
        acc += n;
        if acc >= target {
            return Some(
                LATENCY_BOUNDS
                    .get(i)
                    .copied()
                    .unwrap_or(LATENCY_BOUNDS[LATENCY_BOUNDS.len() - 1] * 2.0),
            );
        }
    }
    None
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct PathAgg {
    pub requests: u64,
    pub s5xx: u64,
    pub rt_sum_ms: f64,
    pub rt_n: u64,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct IpAgg {
    pub requests: u64,
    pub s4xx: u64,
    pub s5xx: u64,
    pub scan: u64,
    /// Missing in summaries persisted before injection detection existed.
    #[serde(default)]
    pub inject: u64,
}

#[derive(Default)]
struct Minute {
    minute: i64,
    requests: u64,
    status: [u64; 4],
    bytes: u64,
    hist: [u64; BUCKETS],
    /// "METHOD path" -> stats
    paths: HashMap<String, PathAgg>,
    ips: HashMap<String, IpAgg>,
    hosts: HashMap<String, u64>,
    ua: HashMap<&'static str, u64>,
    persisted: bool,
}

fn bump<'a, V: Default>(map: &'a mut HashMap<String, V>, key: &str) -> &'a mut V {
    if !map.contains_key(key) && map.len() >= MAP_CAP {
        return map.entry(OTHER.to_string()).or_default();
    }
    map.entry(key.to_string()).or_default()
}

#[derive(Default)]
pub struct Access {
    minutes: Mutex<VecDeque<Minute>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessPoint {
    pub ts: i64,
    pub requests: u64,
    pub s4xx: u64,
    pub s5xx: u64,
    pub p95_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PathStat {
    pub path: String,
    pub requests: u64,
    pub s5xx: u64,
    pub avg_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpStat {
    pub ip: String,
    pub requests: u64,
    pub s4xx: u64,
    pub scan: u64,
    pub inject: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Latency {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub samples: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Count {
    pub key: String,
    pub requests: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessStats {
    pub window_mins: i64,
    pub requests: u64,
    pub requests_per_min: f64,
    /// [2xx, 3xx, 4xx, 5xx]
    pub status: [u64; 4],
    pub error_rate_5xx: f64,
    pub bytes: u64,
    pub series: Vec<AccessPoint>,
    pub top_paths: Vec<PathStat>,
    pub top_ips: Vec<IpStat>,
    /// None when the log format has no request time.
    pub latency: Option<Latency>,
    /// Slowest paths by average request time (at least 5 requests).
    pub slow_paths: Vec<PathStat>,
    pub top_hosts: Vec<Count>,
    pub user_agents: Vec<Count>,
    /// Addresses sending injection payloads, probing scanner paths or getting mostly 4xx.
    pub suspicious: Vec<IpStat>,
}

/// One closed minute, as persisted by the flusher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinuteSummary {
    pub minute: i64,
    pub requests: u64,
    pub status: [u64; 4],
    pub bytes: u64,
    pub hist: Vec<u64>,
    pub paths: Vec<(String, PathAgg)>,
    pub ips: Vec<(String, IpAgg)>,
    pub hosts: Vec<(String, u64)>,
    pub ua: Vec<(String, u64)>,
}

/// Paths and addresses kept per persisted minute.
const PERSIST_TOP: usize = 30;

fn top_n<V: Copy>(m: &HashMap<String, V>, n: usize, key: impl Fn(&V) -> u64) -> Vec<(String, V)> {
    let mut v: Vec<(String, V)> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
    v.sort_by(|a, b| key(&b.1).cmp(&key(&a.1)).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

impl Access {
    pub fn record(&self, line: &str, now_ms: i64) {
        let Some(r) = parse(line) else { return };
        let minute = now_ms / 60_000 * 60_000;
        let mut q = self.minutes.lock().unwrap_or_else(|e| e.into_inner());
        if q.back().is_none_or(|m| m.minute != minute) {
            q.push_back(Minute {
                minute,
                ..Default::default()
            });
            while q.len() > KEEP_MINUTES {
                q.pop_front();
            }
        }
        let m = q.back_mut().expect("just ensured");
        m.requests += 1;
        m.bytes += r.bytes;
        let class = match r.status {
            500..=599 => 3,
            400..=499 => 2,
            300..=399 => 1,
            _ => 0,
        };
        m.status[class] += 1;
        if let Some(rt) = r.rt_ms {
            m.hist[bucket(rt)] += 1;
        }
        let p = bump(&mut m.paths, &format!("{} {}", r.method, r.path));
        p.requests += 1;
        p.s5xx += u64::from(class == 3);
        if let Some(rt) = r.rt_ms {
            p.rt_sum_ms += rt;
            p.rt_n += 1;
        }
        let ip = bump(&mut m.ips, &r.ip);
        ip.requests += 1;
        ip.s4xx += u64::from(class == 2);
        ip.s5xx += u64::from(class == 3);
        ip.scan += u64::from(r.scan);
        ip.inject += u64::from(r.inject);
        if let Some(h) = &r.host {
            *bump(&mut m.hosts, h) += 1;
        }
        *m.ua.entry(ua_class(r.ua.as_deref())).or_default() += 1;
    }

    /// Minutes that ended before `now_ms` and were not handed out yet.
    pub fn drain_closed(&self, now_ms: i64) -> Vec<MinuteSummary> {
        let current = now_ms / 60_000 * 60_000;
        let mut q = self.minutes.lock().unwrap_or_else(|e| e.into_inner());
        q.iter_mut()
            .filter(|m| m.minute < current && !m.persisted)
            .map(|m| {
                m.persisted = true;
                MinuteSummary {
                    minute: m.minute,
                    requests: m.requests,
                    status: m.status,
                    bytes: m.bytes,
                    hist: m.hist.to_vec(),
                    paths: top_n(&m.paths, PERSIST_TOP, |p| p.requests),
                    ips: top_n(&m.ips, PERSIST_TOP, |i| i.requests),
                    hosts: top_n(&m.hosts, 10, |n| *n),
                    ua: m.ua.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
                }
            })
            .collect()
    }

    /// Aggregates the last `window_mins` minutes (1..=60). `mask_ips` hides the host part.
    pub fn stats(&self, window_mins: i64, now_ms: i64, top: usize, mask_ips: bool) -> AccessStats {
        let window = window_mins.clamp(1, KEEP_MINUTES as i64);
        let since = now_ms / 60_000 * 60_000 - (window - 1) * 60_000;
        let q = self.minutes.lock().unwrap_or_else(|e| e.into_inner());
        let mut agg = Agg::default();
        let mut series = Vec::new();
        for m in q.iter().filter(|m| m.minute >= since) {
            agg.add(
                m.requests,
                m.status,
                m.bytes,
                &m.hist,
                m.paths.iter().map(|(k, v)| (k.as_str(), *v)),
                m.ips.iter().map(|(k, v)| (k.as_str(), *v)),
                m.hosts.iter().map(|(k, v)| (k.as_str(), *v)),
                m.ua.iter().map(|(k, v)| (*k, *v)),
            );
            series.push(AccessPoint {
                ts: m.minute,
                requests: m.requests,
                s4xx: m.status[2],
                s5xx: m.status[3],
                p95_ms: quantile(&m.hist, 0.95),
            });
        }
        agg.finish(window, series, top, mask_ips)
    }
}

/// Accumulator shared by the live window and persisted history.
#[derive(Default)]
pub struct Agg {
    requests: u64,
    status: [u64; 4],
    bytes: u64,
    hist: [u64; BUCKETS],
    paths: HashMap<String, PathAgg>,
    ips: HashMap<String, IpAgg>,
    hosts: HashMap<String, u64>,
    ua: HashMap<String, u64>,
}

impl Agg {
    #[allow(clippy::too_many_arguments)]
    pub fn add<'a>(
        &mut self,
        requests: u64,
        status: [u64; 4],
        bytes: u64,
        hist: &[u64],
        paths: impl Iterator<Item = (&'a str, PathAgg)>,
        ips: impl Iterator<Item = (&'a str, IpAgg)>,
        hosts: impl Iterator<Item = (&'a str, u64)>,
        ua: impl Iterator<Item = (&'a str, u64)>,
    ) {
        self.requests += requests;
        self.bytes += bytes;
        for (a, b) in self.status.iter_mut().zip(status) {
            *a += b;
        }
        for (a, b) in self.hist.iter_mut().zip(hist) {
            *a += b;
        }
        for (k, v) in paths {
            let e = self.paths.entry(k.to_string()).or_default();
            e.requests += v.requests;
            e.s5xx += v.s5xx;
            e.rt_sum_ms += v.rt_sum_ms;
            e.rt_n += v.rt_n;
        }
        for (k, v) in ips {
            let e = self.ips.entry(k.to_string()).or_default();
            e.requests += v.requests;
            e.s4xx += v.s4xx;
            e.s5xx += v.s5xx;
            e.scan += v.scan;
            e.inject += v.inject;
        }
        for (k, v) in hosts {
            *self.hosts.entry(k.to_string()).or_default() += v;
        }
        for (k, v) in ua {
            *self.ua.entry(k.to_string()).or_default() += v;
        }
    }

    pub fn add_summary(&mut self, s: &MinuteSummary) {
        self.add(
            s.requests,
            s.status,
            s.bytes,
            &s.hist,
            s.paths.iter().map(|(k, v)| (k.as_str(), *v)),
            s.ips.iter().map(|(k, v)| (k.as_str(), *v)),
            s.hosts.iter().map(|(k, v)| (k.as_str(), *v)),
            s.ua.iter().map(|(k, v)| (k.as_str(), *v)),
        );
    }

    pub fn finish(
        self,
        window: i64,
        series: Vec<AccessPoint>,
        top: usize,
        mask_ips: bool,
    ) -> AccessStats {
        let avg = |p: &PathAgg| (p.rt_n > 0).then(|| p.rt_sum_ms / p.rt_n as f64);
        let path_stat = |(path, p): (String, PathAgg)| PathStat {
            avg_ms: avg(&p),
            path,
            requests: p.requests,
            s5xx: p.s5xx,
        };
        let mut top_paths: Vec<PathStat> = self.paths.clone().into_iter().map(path_stat).collect();
        top_paths.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.path.cmp(&b.path)));
        top_paths.truncate(top);
        let mut slow_paths: Vec<PathStat> = self
            .paths
            .into_iter()
            .filter(|(k, p)| p.requests >= 5 && p.rt_n > 0 && k != OTHER)
            .map(path_stat)
            .collect();
        slow_paths.sort_by(|a, b| {
            b.avg_ms
                .partial_cmp(&a.avg_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.path.cmp(&b.path))
        });
        slow_paths.truncate(top.min(10));

        let mask = |ip: &str| {
            if mask_ips {
                mask_ip(ip)
            } else {
                ip.to_string()
            }
        };
        let mut by_ip: HashMap<String, IpAgg> = HashMap::new();
        for (k, v) in &self.ips {
            let e = by_ip.entry(mask(k)).or_default();
            e.requests += v.requests;
            e.s4xx += v.s4xx;
            e.s5xx += v.s5xx;
            e.scan += v.scan;
            e.inject += v.inject;
        }
        let ip_stat = |(ip, v): (String, IpAgg)| IpStat {
            ip,
            requests: v.requests,
            s4xx: v.s4xx,
            scan: v.scan,
            inject: v.inject,
        };
        let mut suspicious: Vec<IpStat> = by_ip
            .iter()
            .filter(|(k, v)| {
                k.as_str() != OTHER
                    && (v.inject > 0
                        || v.scan >= 5
                        || (v.requests >= 50 && v.s4xx * 2 >= v.requests))
            })
            .map(|(k, v)| ip_stat((k.clone(), *v)))
            .collect();
        suspicious.sort_by(|a, b| {
            b.inject
                .cmp(&a.inject)
                .then(b.scan.cmp(&a.scan))
                .then(b.s4xx.cmp(&a.s4xx))
                .then(a.ip.cmp(&b.ip))
        });
        suspicious.truncate(top);
        let mut top_ips: Vec<IpStat> = by_ip.into_iter().map(ip_stat).collect();
        top_ips.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.ip.cmp(&b.ip)));
        top_ips.truncate(top);

        let counts = |m: HashMap<String, u64>, n: usize| {
            let mut v: Vec<Count> = m
                .into_iter()
                .map(|(key, requests)| Count { key, requests })
                .collect();
            v.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.key.cmp(&b.key)));
            v.truncate(n);
            v
        };
        let samples: u64 = self.hist.iter().sum();
        let latency = (samples > 0).then(|| Latency {
            p50_ms: quantile(&self.hist, 0.5).unwrap_or(0.0),
            p95_ms: quantile(&self.hist, 0.95).unwrap_or(0.0),
            p99_ms: quantile(&self.hist, 0.99).unwrap_or(0.0),
            samples,
        });
        AccessStats {
            window_mins: window,
            requests: self.requests,
            requests_per_min: self.requests as f64 / window.max(1) as f64,
            status: self.status,
            error_rate_5xx: if self.requests > 0 {
                self.status[3] as f64 / self.requests as f64
            } else {
                0.0
            },
            bytes: self.bytes,
            series,
            top_paths,
            top_ips,
            latency,
            slow_paths,
            top_hosts: counts(self.hosts, top.min(10)),
            user_agents: counts(self.ua, 6),
            suspicious,
        }
    }
}

/// 203.0.113.42 -> 203.0.113.x ; 2001:db8:1:2::5 -> 2001:db8:1:2::x
pub fn mask_ip(ip: &str) -> String {
    if ip == OTHER {
        return ip.to_string();
    }
    if let Ok(std::net::IpAddr::V4(v4)) = ip.parse() {
        let o = v4.octets();
        return format!("{}.{}.{}.x", o[0], o[1], o[2]);
    }
    if let Ok(std::net::IpAddr::V6(v6)) = ip.parse() {
        let s = v6.segments();
        return format!("{:x}:{:x}:{:x}:{:x}::x", s[0], s[1], s[2], s[3]);
    }
    "x".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE1: &str = r#"203.0.113.42 - - [18/Nov/2026:10:00:00 +0800] "GET /api/orders/12345?token=abc HTTP/1.1" 200 512 "-" "curl/8""#;
    const LINE2: &str =
        r#"198.51.100.7 - bob [18/Nov/2026:10:00:01 +0800] "POST /login HTTP/2.0" 502 0 "-" "ua""#;

    #[test]
    fn parses_combined_lines() {
        let r = parse(LINE1).unwrap();
        assert_eq!(
            (r.ip.as_str(), r.method.as_str(), r.status, r.bytes),
            ("203.0.113.42", "GET", 200, 512)
        );
        assert!(!r.path.contains("token"), "{}", r.path);
        assert!(!r.path.contains("12345"), "{}", r.path);
        assert_eq!(r.ua.as_deref(), Some("curl/8"));
        assert_eq!(r.rt_ms, None);
        assert!(parse("garbage").is_none());
        // short combined without referer/ua still parses
        assert!(parse(r#"10.0.0.1 - - [x] "GET / HTTP/1.1" 200 1"#).is_some());
    }

    #[test]
    fn detects_injection_payloads() {
        for raw in [
            "/item.php?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users--",
            "/item.php?id=1+union+all+select+1,2,3",
            "/login?user=admin%27+or+%271%27%3D%271",
            "/p?id=1%20AND%201=1",
            "/p?id=1%2527%2520or%25201%253D1", // double-encoded
            "/p?id=1;select%20pg_sleep(5)",
            "/p?id=sleep(5)",
            "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "/p?u=%24%7Bjndi:ldap://x/a%7D",
            "/download?file=../../../etc/passwd",
        ] {
            assert!(is_injection(raw), "{raw}");
        }
        for raw in [
            "/",
            "/search?q=rock+and+roll",
            "/blog/union-station-select-menu",
            "/api/items?sort=created_at&order=desc&page=2",
            "/p?q=it%27s+fine",
            "/static/app.3f2a.js",
            "/docs/or-1-2",
        ] {
            assert!(!is_injection(raw), "{raw}");
        }
        let r = parse(
            r#"10.0.0.7 - - [x] "GET /p?id=1%27%20or%201=1-- HTTP/1.1" 200 10 "-" "Mozilla/5.0""#,
        )
        .unwrap();
        assert!(r.inject && !r.scan);
        assert_eq!(r.path, "/p");
    }

    #[test]
    fn parses_timed_and_json_lines() {
        let timed = format!("{LINE1} 0.250 host=Shop.Example.com");
        let r = parse(&timed).unwrap();
        assert_eq!(r.rt_ms, Some(250.0));
        assert_eq!(r.host.as_deref(), Some("shop.example.com"));
        let rt = parse(&format!("{LINE2} rt=1.5 uct=\"0.001\"")).unwrap();
        assert_eq!(rt.rt_ms, Some(1500.0));

        let j = r#"{"time":"x","remote_addr":"192.0.2.9","request":"GET /.env HTTP/1.1","status":"404","body_bytes_sent":"0","request_time":"0.004","http_user_agent":"zgrab/0.x","host":"api.example.com"}"#;
        let r = parse(j).unwrap();
        assert_eq!(
            (r.ip.as_str(), r.status, r.rt_ms),
            ("192.0.2.9", 404, Some(4.0))
        );
        assert!(r.scan);
        assert_eq!(ua_class(r.ua.as_deref()), "scanner");
        let j2 = r#"{"remote_addr":"192.0.2.10","request_method":"POST","request_uri":"/api/pay?x=1","status":201,"request_time":0.9}"#;
        let r = parse(j2).unwrap();
        assert_eq!((r.method.as_str(), r.status), ("POST", 201));
        assert!((r.rt_ms.unwrap() - 900.0).abs() < 1e-6);
        assert!(parse(r#"{"msg":"not an access line"}"#).is_none());
    }

    #[test]
    fn ua_classes_and_quantiles() {
        assert_eq!(
            ua_class(Some("Mozilla/5.0 (X11; Linux) Firefox/130")),
            "browser"
        );
        assert_eq!(ua_class(Some("Googlebot/2.1")), "bot");
        assert_eq!(ua_class(Some("python-requests/2.32")), "tool");
        assert_eq!(ua_class(None), "empty");
        let mut h = [0u64; BUCKETS];
        h[bucket(3.0)] = 90;
        h[bucket(800.0)] = 10;
        assert_eq!(quantile(&h, 0.5), Some(5.0));
        assert_eq!(quantile(&h, 0.95), Some(1000.0));
        assert_eq!(quantile(&[0; BUCKETS], 0.5), None);
    }

    #[test]
    fn aggregates_and_masks() {
        let a = Access::default();
        let t = 1_700_000_000_000;
        for _ in 0..3 {
            a.record(LINE1, t);
        }
        a.record(LINE2, t + 61_000);
        let s = a.stats(15, t + 61_000, 10, true);
        assert_eq!(s.requests, 4);
        assert_eq!(s.status, [3, 0, 0, 1]);
        assert_eq!(s.series.len(), 2);
        assert_eq!(s.top_ips[0].ip, "203.0.113.x");
        assert_eq!(s.top_paths[0].requests, 3);
        assert_eq!(
            s.top_paths
                .iter()
                .find(|p| p.path.starts_with("POST"))
                .unwrap()
                .s5xx,
            1
        );
        assert!(s.latency.is_none());
        let raw = a.stats(1, t + 61_000, 10, false);
        assert_eq!(raw.requests, 1);
        assert_eq!(raw.top_ips[0].ip, "198.51.100.7");
    }

    #[test]
    fn slow_paths_suspicious_ips_and_drain() {
        let a = Access::default();
        let t = 1_700_000_000_000;
        for i in 0..10 {
            a.record(
                &format!(
                    r#"10.0.0.1 - - [x] "GET /slow HTTP/1.1" 200 1 "-" "Mozilla/5.0" {}.5"#,
                    i % 2
                ),
                t,
            );
            a.record(
                r#"10.0.0.1 - - [x] "GET /fast HTTP/1.1" 200 1 "-" "Mozilla/5.0" 0.002"#,
                t,
            );
            a.record(
                &format!(r#"192.0.2.66 - - [x] "GET /wp-login.php?{i} HTTP/1.1" 404 0 "-" "-""#),
                t,
            );
        }
        let s = a.stats(5, t, 10, false);
        assert_eq!(s.slow_paths[0].path, "GET /slow");
        assert!(s.latency.as_ref().unwrap().p95_ms >= 1000.0);
        assert_eq!(s.suspicious.len(), 1);
        assert_eq!(s.suspicious[0].ip, "192.0.2.66");
        assert_eq!(s.suspicious[0].scan, 10);
        assert!(
            s.user_agents
                .iter()
                .any(|c| c.key == "browser" && c.requests == 20)
        );

        // the running minute is not drained; once closed it is drained exactly once
        assert!(a.drain_closed(t).is_empty());
        let d = a.drain_closed(t + 60_000);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].requests, 30);
        assert!(a.drain_closed(t + 120_000).is_empty());
        // a persisted summary aggregates to the same numbers
        let mut agg = Agg::default();
        agg.add_summary(&d[0]);
        let h = agg.finish(5, vec![], 10, false);
        assert_eq!(h.requests, 30);
        assert_eq!(h.suspicious[0].scan, 10);
    }

    #[test]
    fn maps_are_bounded() {
        let a = Access::default();
        for i in 0..(MAP_CAP + 50) {
            a.record(
                &format!(
                    r#"10.0.{}.{} - - [x] "GET /p{i}x HTTP/1.1" 200 1"#,
                    i / 250,
                    i % 250
                ),
                0,
            );
        }
        let q = a.minutes.lock().unwrap();
        assert!(q[0].ips.len() <= MAP_CAP + 1);
        assert!(q[0].paths.len() <= MAP_CAP + 1);
    }
}
