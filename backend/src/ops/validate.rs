//! Argument validation shared by the daemon (early, friendly errors) and the helper (the
//! authoritative check). Everything that ends up in an argv or a path goes through here.

use std::net::IpAddr;

use super::proto::{OpError, OpResult};

fn bad(msg: impl Into<String>) -> OpError {
    OpError::invalid(msg)
}

/// Container id (hex prefix) or name: `[A-Za-z0-9][A-Za-z0-9_.-]{0,127}`.
pub fn container_ref(s: &str) -> OpResult<&str> {
    let b = s.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c));
    ok.then_some(s)
        .ok_or_else(|| bad(format!("无效的容器 ID 或名称：{s:?}")))
}

/// Image reference such as `nginx:1.27`, `ghcr.io/org/app@sha256:...` or an image id.
pub fn image_ref(s: &str) -> OpResult<&str> {
    let b = s.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 255
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-/:@".contains(c));
    ok.then_some(s)
        .ok_or_else(|| bad(format!("无效的镜像名：{s:?}")))
}

/// Compose project / volume name: `[a-z0-9][a-z0-9_.-]*` (case-insensitive), at most 128.
pub fn simple_name(kind: &str, s: &str) -> OpResult<String> {
    let b = s.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c));
    ok.then(|| s.to_string())
        .ok_or_else(|| bad(format!("无效的{kind}名称：{s:?}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Any,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Any => "any",
        }
    }
}

/// A single port or an inclusive range `lo:hi` / `lo-hi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSpec {
    pub lo: u16,
    pub hi: u16,
}

impl PortSpec {
    pub fn parse(s: &str) -> OpResult<Self> {
        let s = s.trim();
        let (a, b) = s
            .split_once(':')
            .or_else(|| s.split_once('-'))
            .unwrap_or((s, s));
        let p = |x: &str| {
            x.trim()
                .parse::<u16>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or_else(|| bad(format!("无效的端口：{s:?}")))
        };
        let (lo, hi) = (p(a)?, p(b)?);
        if lo > hi {
            return Err(bad(format!("端口范围颠倒：{s:?}")));
        }
        Ok(Self { lo, hi })
    }

    pub fn contains(self, port: u16) -> bool {
        (self.lo..=self.hi).contains(&port)
    }

    /// `22` or `8000:8100` (ufw / firewalld use `-` for ranges, see callers).
    pub fn display(self, sep: char) -> String {
        if self.lo == self.hi {
            self.lo.to_string()
        } else {
            format!("{}{sep}{}", self.lo, self.hi)
        }
    }
}

/// An address or CIDR block; returned in canonical text form.
pub fn cidr(s: &str) -> OpResult<String> {
    let s = s.trim();
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let ip: IpAddr = addr
        .parse()
        .map_err(|_| bad(format!("无效的来源地址：{s:?}")))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    match len {
        None => Ok(ip.to_string()),
        Some(l) => {
            let n: u8 = l
                .parse()
                .ok()
                .filter(|n| *n <= max)
                .ok_or_else(|| bad(format!("无效的前缀长度：{s:?}")))?;
            Ok(format!("{ip}/{n}"))
        }
    }
}

/// Unix user name as found in /etc/passwd.
pub fn user_name(s: &str) -> OpResult<&str> {
    let b = s.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_lowercase() || b[0] == b'_' || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c));
    ok.then_some(s)
        .ok_or_else(|| bad(format!("无效的用户名：{s:?}")))
}

/// nginx site or file name component: no separators, no leading dot.
pub fn file_name(s: &str) -> OpResult<&str> {
    let b = s.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 128
        && b[0] != b'.'
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(c));
    ok.then_some(s)
        .ok_or_else(|| bad(format!("无效的文件名：{s:?}")))
}

/// Relative path made only of [`file_name`] components, e.g. `sites-available/app.conf`.
pub fn rel_path(s: &str) -> OpResult<Vec<String>> {
    if s.is_empty() || s.len() > 512 || s.starts_with('/') {
        return Err(bad(format!("无效的路径：{s:?}")));
    }
    s.split('/')
        .map(|c| file_name(c).map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_and_names() {
        assert!(container_ref("web-1").is_ok());
        assert!(container_ref("3f2a9c").is_ok());
        assert!(container_ref("-rm").is_err());
        assert!(container_ref("a b").is_err());
        assert!(image_ref("ghcr.io/org/app:1.2@sha256:abc").is_ok());
        assert!(image_ref("--help").is_err());
        assert!(image_ref("x;rm").is_err());
        assert!(user_name("deploy").is_ok());
        assert!(user_name("../root").is_err());
        assert!(rel_path("sites-available/app.conf").is_ok());
        assert!(rel_path("../etc/passwd").is_err());
        assert!(rel_path("conf.d/.hidden").is_err());
        assert!(rel_path("/etc/nginx/x").is_err());
    }

    #[test]
    fn ports_and_cidrs() {
        assert_eq!(PortSpec::parse("22").unwrap(), PortSpec { lo: 22, hi: 22 });
        let r = PortSpec::parse("8000:8100").unwrap();
        assert!(r.contains(8050) && !r.contains(22));
        assert_eq!(r.display('-'), "8000-8100");
        assert!(PortSpec::parse("0").is_err());
        assert!(PortSpec::parse("90:80").is_err());
        assert!(PortSpec::parse("22;reboot").is_err());
        assert_eq!(cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(cidr(" 203.0.113.7 ").unwrap(), "203.0.113.7");
        assert_eq!(cidr("2001:db8::/32").unwrap(), "2001:db8::/32");
        assert!(cidr("10.0.0.0/33").is_err());
        assert!(cidr("any").is_err());
    }
}
