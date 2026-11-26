//! Running fixed argv commands from the helper: never through a shell, stdin closed, C locale,
//! bounded output and a timeout.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncReadExt;

use super::Log;

/// Output kept per stream.
const MAX_OUT: usize = 512 * 1024;

#[derive(Debug, Clone)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
    /// stderr, or stdout when stderr is empty; trimmed.
    pub fn message(&self) -> String {
        let s = if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        };
        s.trim().to_string()
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

pub fn argv(v: &[&str]) -> Vec<String> {
    s(v)
}

async fn read_capped(mut r: impl tokio::io::AsyncRead + Unpin) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < MAX_OUT {
                    buf.extend_from_slice(&chunk[..n.min(MAX_OUT - buf.len())]);
                }
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Runs `argv` and captures its output. Fails only when the command cannot be started or
/// times out; a non-zero exit is returned in [`Output::code`].
pub async fn run(argv: &[String], timeout: Duration) -> Result<Output> {
    let mut child = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {}", argv[0]))?;
    let out = child.stdout.take().context("stdout")?;
    let err = child.stderr.take().context("stderr")?;
    let fut = async {
        let (o, e) = tokio::join!(read_capped(out), read_capped(err));
        let code = child.wait().await?.code().unwrap_or(-1);
        anyhow::Ok(Output {
            code,
            stdout: o,
            stderr: e,
        })
    };
    tokio::time::timeout(timeout, fut)
        .await
        .with_context(|| format!("{} timed out after {}s", argv[0], timeout.as_secs()))?
}

/// Like [`run`], but echoes the command line and its output to the job log.
pub async fn run_logged(log: &Log, argv: &[String], timeout: Duration) -> Result<Output> {
    log.line(format!("$ {}", argv.join(" ")));
    let out = run(argv, timeout).await?;
    for l in out.stdout.lines().chain(out.stderr.lines()) {
        if !l.trim().is_empty() {
            log.line(l.to_string());
        }
    }
    if !out.ok() {
        log.line(format!("（退出码 {}）", out.code));
    }
    Ok(out)
}

/// True when `systemctl` manages `unit` on this host.
pub async fn unit_loaded(unit: &str) -> bool {
    if crate::sandbox::which("systemctl").is_none() {
        return false;
    }
    run(
        &s(&["systemctl", "show", "-p", "LoadState", "--value", unit]),
        Duration::from_secs(10),
    )
    .await
    .is_ok_and(|o| o.stdout.trim() == "loaded")
}

pub async fn unit_active(unit: &str) -> bool {
    crate::sandbox::which("systemctl").is_some()
        && run(
            &s(&["systemctl", "is-active", "--quiet", unit]),
            Duration::from_secs(10),
        )
        .await
        .is_ok_and(|o| o.ok())
}
