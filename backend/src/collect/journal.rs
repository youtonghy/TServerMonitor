//! systemd journal as a log source (read-only): follows `journalctl -f -o json` from now on.
//!
//! * Entries at or above `[journal] max_priority` (default warning) from any unit go to the
//!   `journal` source; every entry of a unit listed in `units` goes to `journal:<unit>`.
//! * sshd entries are also handed to the security collector, so login auditing works on hosts
//!   that have no `/var/log/auth.log` / `/var/log/secure`.
//!
//! The daemon user needs read access to the journal (`systemd-journal` or `adm` group).

use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::config::LogKind;
use crate::state::Shared;

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "MESSAGE")]
    message: Option<serde_json::Value>,
    #[serde(rename = "PRIORITY")]
    priority: Option<String>,
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    ident: Option<String>,
    #[serde(rename = "_SYSTEMD_UNIT")]
    unit: Option<String>,
}

/// Where one journal entry goes.
#[derive(Debug, PartialEq)]
pub struct Routed {
    /// log pipeline source and line, if it is ingested
    pub log: Option<(String, String)>,
    /// sshd line for the login audit
    pub auth: Option<String>,
}

/// Routes one `journalctl -o json` line. Binary messages (arrays) are skipped.
pub fn route(line: &str, max_priority: u8, units: &[String]) -> Option<Routed> {
    let e: Entry = serde_json::from_str(line).ok()?;
    let msg = e.message.as_ref()?.as_str()?.trim();
    if msg.is_empty() {
        return None;
    }
    let prio: u8 = e
        .priority
        .as_deref()
        .and_then(|p| p.parse().ok())
        .unwrap_or(6);
    let ident = e.ident.as_deref().unwrap_or("-");
    let unit = e.unit.as_deref().unwrap_or("");
    let auth = matches!(ident, "sshd" | "sshd-session").then(|| format!("{ident}: {msg}"));
    let level = match prio {
        0..=3 => "error ",
        4 => "warning ",
        _ => "",
    };
    let text = format!("{level}{ident}: {msg}");
    let wanted = units
        .iter()
        .find(|u| unit == u.as_str() || unit.strip_suffix(".service") == Some(u.as_str()));
    let log = match wanted {
        Some(u) => Some((format!("journal:{u}"), text)),
        None if prio <= max_priority => Some(("journal".to_string(), text)),
        None => None,
    };
    (log.is_some() || auth.is_some()).then_some(Routed { log, auth })
}

pub fn spawn(state: &Shared) {
    let cfg = &state.cfg.journal;
    if !cfg.enabled {
        state.set_collector("journal", false, Some("已在配置中关闭".into()));
        return;
    }
    if !cfg!(target_os = "linux") || crate::sandbox::which("journalctl").is_none() {
        state.set_collector("journal", false, Some("本机没有 journalctl，已跳过".into()));
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        let p = crate::collect::pipeline();
        p.register("journal", LogKind::Generic, None, None);
        for u in &state.cfg.journal.units {
            p.register(&format!("journal:{u}"), LogKind::Generic, None, None);
        }
        loop {
            if let Err(e) = follow(&state).await {
                tracing::warn!("journal: {e:#}");
                state.set_collector("journal", false, Some(format!("{e:#}")));
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

async fn follow(state: &Shared) -> anyhow::Result<()> {
    let cfg = &state.cfg.journal;
    let mut child = tokio::process::Command::new("journalctl")
        .args(["-f", "-o", "json", "-n", "0", "--no-pager"])
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let out = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdout"))?;
    state.set_collector("journal", true, None);
    let mut lines = BufReader::new(out).lines();
    let p = crate::collect::pipeline();
    while let Some(l) = lines.next_line().await? {
        let Some(r) = route(&l, cfg.max_priority, &cfg.units) else {
            continue;
        };
        if let Some(a) = r.auth {
            crate::collect::security::push_auth_line(a);
        }
        if let Some((src, text)) = r.log {
            p.ingest(&src, LogKind::Generic, &text);
        }
    }
    let status = child.wait().await?;
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        use tokio::io::AsyncReadExt;
        let _ = e.read_to_string(&mut err).await;
    }
    anyhow::bail!("journalctl exited ({status}): {}", err.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_entries() {
        let units = vec!["nginx".to_string()];
        let warn = r#"{"MESSAGE":"disk almost full","PRIORITY":"4","SYSLOG_IDENTIFIER":"kernel"}"#;
        let r = route(warn, 4, &units).unwrap();
        assert_eq!(
            r.log,
            Some(("journal".into(), "warning kernel: disk almost full".into()))
        );
        let info = r#"{"MESSAGE":"started","PRIORITY":"6","SYSLOG_IDENTIFIER":"systemd"}"#;
        assert!(route(info, 4, &units).is_none());
        let unit = r#"{"MESSAGE":"GET /","PRIORITY":"6","SYSLOG_IDENTIFIER":"nginx","_SYSTEMD_UNIT":"nginx.service"}"#;
        assert_eq!(
            route(unit, 4, &units).unwrap().log.unwrap().0,
            "journal:nginx"
        );
        let ssh = r#"{"MESSAGE":"Failed password for root from 203.0.113.9 port 22 ssh2","PRIORITY":"6","SYSLOG_IDENTIFIER":"sshd-session"}"#;
        let r = route(ssh, 4, &units).unwrap();
        assert!(r.log.is_none());
        assert!(r.auth.unwrap().contains("Failed password"));
        assert!(route(r#"{"MESSAGE":[1,2,3],"PRIORITY":"2"}"#, 4, &units).is_none());
        assert!(route("not json", 4, &units).is_none());
    }
}
