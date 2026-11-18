//! Real-time access analysis for `nginx_access` sources (combined log format): per-minute
//! request counts, status classes and bytes, plus the busiest paths and client addresses.
//! Kept in memory for the last hour with bounded maps, so a flood of distinct paths or IPs
//! cannot grow it without limit.

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};

use regex::Regex;
use serde::Serialize;

const KEEP_MINUTES: usize = 60;
/// Distinct paths / addresses tracked per minute; the rest is counted under "(other)".
const MAP_CAP: usize = 2000;
const OTHER: &str = "(other)";

/// `ip - user [time] "METHOD path PROTO" status bytes ...`
static LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(\S+) \S+ \S+ \[[^\]]*\] "([A-Z]{3,10}) ([^ "]+)[^"]*" (\d{3}) (\d+|-)"#)
        .expect("static regex")
});

#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub ip: &'a str,
    pub method: &'a str,
    pub path: String,
    pub status: u16,
    pub bytes: u64,
}

/// Parses one combined-format line; the path loses its query string and gets ids templated.
pub fn parse(line: &str) -> Option<Request<'_>> {
    let c = LINE.captures(line)?;
    let raw_path = c.get(3)?.as_str();
    let path = raw_path.split(['?', '#']).next().unwrap_or(raw_path);
    Some(Request {
        ip: c.get(1)?.as_str(),
        method: c.get(2)?.as_str(),
        path: crate::preprocess::template(&crate::preprocess::redact(path)),
        status: c.get(4)?.as_str().parse().ok()?,
        bytes: c.get(5)?.as_str().parse().unwrap_or(0),
    })
}

#[derive(Default)]
struct Minute {
    minute: i64,
    requests: u64,
    status: [u64; 4],
    bytes: u64,
    /// "METHOD path" -> (requests, 5xx)
    paths: HashMap<String, (u64, u64)>,
    ips: HashMap<String, u64>,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct PathStat {
    pub path: String,
    pub requests: u64,
    pub s5xx: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpStat {
    pub ip: String,
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
        let p = bump(&mut m.paths, &format!("{} {}", r.method, r.path));
        p.0 += 1;
        p.1 += u64::from(class == 3);
        *bump(&mut m.ips, r.ip) += 1;
    }

    /// Aggregates the last `window_mins` minutes (1..=60). `mask_ips` hides the host part.
    pub fn stats(&self, window_mins: i64, now_ms: i64, top: usize, mask_ips: bool) -> AccessStats {
        let window = window_mins.clamp(1, KEEP_MINUTES as i64);
        let since = now_ms / 60_000 * 60_000 - (window - 1) * 60_000;
        let q = self.minutes.lock().unwrap_or_else(|e| e.into_inner());
        let mut status = [0u64; 4];
        let (mut requests, mut bytes) = (0, 0);
        let mut paths: HashMap<&str, (u64, u64)> = HashMap::new();
        let mut ips: HashMap<String, u64> = HashMap::new();
        let mut series = Vec::new();
        for m in q.iter().filter(|m| m.minute >= since) {
            requests += m.requests;
            bytes += m.bytes;
            for (a, b) in status.iter_mut().zip(m.status) {
                *a += b;
            }
            for (k, v) in &m.paths {
                let e = paths.entry(k).or_default();
                e.0 += v.0;
                e.1 += v.1;
            }
            for (k, v) in &m.ips {
                let key = if mask_ips { mask_ip(k) } else { k.clone() };
                *ips.entry(key).or_default() += v;
            }
            series.push(AccessPoint {
                ts: m.minute,
                requests: m.requests,
                s4xx: m.status[2],
                s5xx: m.status[3],
            });
        }
        let mut top_paths: Vec<PathStat> = paths
            .into_iter()
            .map(|(p, (r, e))| PathStat {
                path: p.to_string(),
                requests: r,
                s5xx: e,
            })
            .collect();
        top_paths.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.path.cmp(&b.path)));
        top_paths.truncate(top);
        let mut top_ips: Vec<IpStat> = ips
            .into_iter()
            .map(|(ip, requests)| IpStat { ip, requests })
            .collect();
        top_ips.sort_by(|a, b| b.requests.cmp(&a.requests).then(a.ip.cmp(&b.ip)));
        top_ips.truncate(top);
        AccessStats {
            window_mins: window,
            requests,
            requests_per_min: requests as f64 / window as f64,
            status,
            error_rate_5xx: if requests > 0 {
                status[3] as f64 / requests as f64
            } else {
                0.0
            },
            bytes,
            series,
            top_paths,
            top_ips,
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
            (r.ip, r.method, r.status, r.bytes),
            ("203.0.113.42", "GET", 200, 512)
        );
        assert!(!r.path.contains("token"), "{}", r.path);
        assert!(!r.path.contains("12345"), "{}", r.path);
        assert!(parse("garbage").is_none());
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
        let raw = a.stats(1, t + 61_000, 10, false);
        assert_eq!(raw.requests, 1);
        assert_eq!(raw.top_ips[0].ip, "198.51.100.7");
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
