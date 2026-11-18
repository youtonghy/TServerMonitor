//! Pending package updates for apt, dnf and Homebrew, listed without privileges and without
//! touching the host: apt uses a simulated upgrade, dnf reads its cache only, and Homebrew is
//! told not to auto-update. The list is refreshed every 6 hours or on demand.

use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::model::now_ms;
use crate::state::Shared;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Package {
    pub manager: &'static str,
    pub name: String,
    pub current: Option<String>,
    pub available: String,
    pub source: Option<String>,
    pub security: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PackageReport {
    pub checked_at: Option<i64>,
    pub managers: Vec<&'static str>,
    pub packages: Vec<Package>,
    pub errors: Vec<String>,
    /// Running inside a container: the list describes the container image, not the host.
    pub in_container: bool,
}

static LAST: LazyLock<Mutex<PackageReport>> = LazyLock::new(Mutex::default);

pub fn last() -> PackageReport {
    LAST.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);

pub fn spawn(state: &Shared) {
    let state = state.clone();
    tokio::spawn(async move {
        // let the host settle after start-up before running package tools
        tokio::time::sleep(Duration::from_secs(90)).await;
        loop {
            if !state.is_yielding() {
                check(&state).await;
            }
            tokio::time::sleep(CHECK_EVERY).await;
        }
    });
}

/// Re-lists pending updates now and stores the result.
pub async fn check(state: &Shared) -> PackageReport {
    let report = collect().await;
    state.set_collector(
        "packages",
        report.errors.is_empty(),
        Some(if report.managers.is_empty() {
            "未检测到 apt、dnf 或 Homebrew".into()
        } else {
            format!(
                "{}：{} 个待更新",
                report.managers.join("/"),
                report.packages.len()
            )
        }),
    );
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = report.clone();
    report
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    crate::sandbox::which(bin)
}

async fn run(cmd: &Path, args: &[&str], env: &[(&str, &str)]) -> Result<(i32, String), String> {
    let mut c = tokio::process::Command::new(cmd);
    c.args(args)
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    for (k, v) in env {
        c.env(k, v);
    }
    match tokio::time::timeout(Duration::from_secs(180), c.output()).await {
        Ok(Ok(out)) => Ok((
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )),
        Ok(Err(e)) => Err(format!("{}: {e}", cmd.display())),
        Err(_) => Err(format!("{} timed out", cmd.display())),
    }
}

async fn collect() -> PackageReport {
    let mut r = PackageReport {
        checked_at: Some(now_ms()),
        in_container: Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists(),
        ..Default::default()
    };
    if let Some(apt) = which("apt-get") {
        r.managers.push("apt");
        // -s simulates: nothing is downloaded or installed and the index is not refreshed
        match run(&apt, &["-s", "-o", "Debug::NoLocking=1", "upgrade"], &[]).await {
            Ok((_, out)) => r.packages.extend(parse_apt(&out)),
            Err(e) => r.errors.push(e),
        }
    }
    if let Some(dnf) = which("dnf") {
        r.managers.push("dnf");
        // check-update exits 100 when updates exist
        match run(&dnf, &["-q", "--cacheonly", "check-update"], &[]).await {
            Ok((code, out)) if code == 0 || code == 100 => {
                let security = match run(
                    &dnf,
                    &["-q", "--cacheonly", "updateinfo", "list", "--security"],
                    &[],
                )
                .await
                {
                    Ok((_, s)) => s,
                    Err(_) => String::new(),
                };
                r.packages.extend(parse_dnf(&out, &security));
            }
            Ok((code, _)) => r.errors.push(format!("dnf check-update exited {code}")),
            Err(e) => r.errors.push(e),
        }
    }
    if let Some(brew) = which("brew") {
        r.managers.push("brew");
        let env = [
            ("HOMEBREW_NO_AUTO_UPDATE", "1"),
            ("HOMEBREW_NO_ANALYTICS", "1"),
            ("HOMEBREW_NO_ENV_HINTS", "1"),
            ("NO_COLOR", "1"),
        ];
        match run(&brew, &["outdated", "--json=v2"], &env).await {
            Ok((_, out)) => match parse_brew(&out) {
                Ok(p) => r.packages.extend(p),
                Err(e) => r.errors.push(format!("brew outdated: {e}")),
            },
            Err(e) => r.errors.push(e),
        }
    }
    r.packages.sort_by(|a, b| {
        b.security
            .cmp(&a.security)
            .then(a.manager.cmp(b.manager))
            .then(a.name.cmp(&b.name))
    });
    r
}

/// `Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-security [amd64])`
pub fn parse_apt(sim: &str) -> Vec<Package> {
    sim.lines()
        .filter_map(|l| l.strip_prefix("Inst "))
        .filter_map(|rest| {
            let mut it = rest.splitn(2, ' ');
            let name = it.next()?.to_string();
            let rest = it.next().unwrap_or("");
            let current = rest
                .strip_prefix('[')
                .and_then(|r| r.split_once(']'))
                .map(|(v, _)| v.to_string());
            let paren = rest.split_once('(')?.1.trim_end_matches(')');
            let mut parts = paren.split_whitespace();
            let available = parts.next()?.to_string();
            let source = parts.next().map(str::to_string);
            let security = source
                .as_deref()
                .is_some_and(|s| s.to_ascii_lowercase().contains("security"));
            Some(Package {
                manager: "apt",
                name,
                current,
                available,
                source,
                security,
            })
        })
        .collect()
}

/// `check-update`: `name.arch  version  repo`; `updateinfo list --security`: `ID  sev/Sec.  nevra`.
pub fn parse_dnf(out: &str, security: &str) -> Vec<Package> {
    let secure: Vec<String> = security
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .map(str::to_string)
        .collect();
    out.lines()
        // a blank line separates updates from the "Obsoleting Packages" section
        .take_while(|l| !l.starts_with("Obsoleting"))
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            let (na, ver, repo) = (p.next()?, p.next()?, p.next()?);
            if p.next().is_some() || !na.contains('.') {
                return None;
            }
            let name = na
                .rsplit_once('.')
                .map(|(n, _)| n)
                .unwrap_or(na)
                .to_string();
            let security = secure.iter().any(|s| s.starts_with(&format!("{name}-")));
            Some(Package {
                manager: "dnf",
                name,
                current: None,
                available: ver.to_string(),
                source: Some(repo.to_string()),
                security,
            })
        })
        .collect()
}

pub fn parse_brew(json: &str) -> Result<Vec<Package>, String> {
    let v: serde_json::Value = serde_json::from_str(json.trim()).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for (key, kind) in [("formulae", "formula"), ("casks", "cask")] {
        for p in v[key].as_array().into_iter().flatten() {
            let Some(name) = p["name"].as_str() else {
                continue;
            };
            out.push(Package {
                manager: "brew",
                name: name.to_string(),
                current: p["installed_versions"]
                    .as_array()
                    .and_then(|a| a.last())
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                available: p["current_version"].as_str().unwrap_or("").to_string(),
                source: Some(kind.into()),
                security: false,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_simulation() {
        let out = "NOTE: This is only a simulation!\nInst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-security [amd64])\nInst tzdata (2024a-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])\nConf openssl (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-security [amd64])\n";
        let p = parse_apt(out);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "openssl");
        assert_eq!(p[0].current.as_deref(), Some("3.0.2-0ubuntu1.10"));
        assert_eq!(p[0].available, "3.0.2-0ubuntu1.12");
        assert!(p[0].security);
        assert_eq!(p[1].current, None);
        assert!(!p[1].security);
    }

    #[test]
    fn dnf_check_update() {
        let out = "\nkernel.x86_64    5.14.0-427.el9    baseos\nopenssh-server.x86_64   8.7p1-38.el9   baseos\nObsoleting Packages\ngrub2-tools.x86_64  1:2.06-80.el9  baseos\n";
        let sec = "RHSA-2024:1234 Important/Sec. openssh-server-8.7p1-38.el9.x86_64\n";
        let p = parse_dnf(out, sec);
        assert_eq!(p.len(), 2);
        assert_eq!(p[1].name, "openssh-server");
        assert!(p[1].security);
        assert!(!p[0].security);
    }

    #[test]
    fn brew_json() {
        let j = r#"{"formulae":[{"name":"node","installed_versions":["22.1.0"],"current_version":"22.2.0","pinned":false}],"casks":[{"name":"firefox","installed_versions":["126.0"],"current_version":"127.0"}]}"#;
        let p = parse_brew(j).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].current.as_deref(), Some("22.1.0"));
        assert_eq!(p[1].source.as_deref(), Some("cask"));
        assert!(parse_brew("not json").is_err());
    }
}
