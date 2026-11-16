//! Isolated workspace for AI-authored analysis scripts.
//!
//! * All files the agent writes live under `<data_dir>/workspace`; paths are validated
//!   (no absolute paths, no `..`, no symlinks) before any I/O.
//! * Python runs through `tsmonitor __sandbox-exec`, a tiny launcher that applies resource
//!   limits and (on Linux) a Landlock ruleset — read-only system dirs, read-write workspace,
//!   no network on kernels with Landlock ABI v4+ — then execs the interpreter.
//! * The environment is cleared, the process gets its own process group, a wall-clock
//!   timeout and a cap on captured output.

use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::io::AsyncReadExt;

use crate::config::SandboxConfig;

pub const SUBDIRS: &[&str] = &["scripts", "samples", "cache", "tmp"];
const MAX_SCRIPT_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathError {
    #[error("path must be relative to the workspace")]
    Absolute,
    #[error("path must not contain '..' or special components")]
    Traversal,
    #[error("path must not be empty")]
    Empty,
    #[error("symlinks are not allowed in the workspace")]
    Symlink,
    #[error("path escapes the workspace")]
    Escapes,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunOutput {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
}

pub struct Sandbox {
    root: PathBuf,
    cfg: SandboxConfig,
    launcher: PathBuf,
}

impl Sandbox {
    pub fn init(data_dir: &Path, cfg: SandboxConfig) -> Result<Self> {
        let root = data_dir.join("workspace");
        for d in SUBDIRS {
            std::fs::create_dir_all(root.join(d))
                .with_context(|| format!("creating workspace dir {d}"))?;
        }
        let root = root.canonicalize()?;
        let launcher = std::env::current_exe().context("locating own executable")?;
        Ok(Self {
            root,
            cfg,
            launcher,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Uses another launcher binary (tests run outside the `tsmonitor` executable).
    pub fn with_launcher(mut self, launcher: PathBuf) -> Self {
        self.launcher = launcher;
        self
    }

    /// Validates a workspace-relative path and returns the absolute path.
    pub fn resolve(&self, rel: &str) -> Result<PathBuf, PathError> {
        let rel = rel.trim();
        if rel.is_empty() || rel.contains('\0') {
            return Err(PathError::Empty);
        }
        let p = Path::new(rel);
        if p.is_absolute() || rel.starts_with('~') {
            return Err(PathError::Absolute);
        }
        let mut out = self.root.clone();
        for c in p.components() {
            match c {
                Component::Normal(part) => {
                    out.push(part);
                    // every existing component must be a real file or directory
                    if let Ok(meta) = std::fs::symlink_metadata(&out)
                        && meta.file_type().is_symlink()
                    {
                        return Err(PathError::Symlink);
                    }
                }
                Component::CurDir => {}
                _ => return Err(PathError::Traversal),
            }
        }
        if out == self.root {
            return Err(PathError::Empty);
        }
        if !out.starts_with(&self.root) {
            return Err(PathError::Escapes);
        }
        Ok(out)
    }

    pub fn write_file(&self, rel: &str, content: &[u8], max: usize) -> Result<PathBuf> {
        if content.len() > max {
            bail!("file too large ({} bytes, limit {max})", content.len());
        }
        let path = self.resolve(rel)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            // re-check after creating parents: nothing in between may be a symlink
            self.resolve(rel)?;
        }
        std::fs::write(&path, content)?;
        Ok(path)
    }

    pub fn write_script(&self, name: &str, content: &str) -> Result<String> {
        if !is_safe_name(name) || !name.ends_with(".py") {
            bail!("script name must match [A-Za-z0-9_.-]+ and end with .py");
        }
        let rel = format!("scripts/{name}");
        self.write_file(&rel, content.as_bytes(), MAX_SCRIPT_BYTES)?;
        Ok(rel)
    }

    pub fn list(&self) -> Vec<FileEntry> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                    continue;
                };
                // venv internals are noise for the model
                if meta.is_dir() && e.file_name() != "venv" {
                    stack.push(e.path());
                } else if meta.is_file() {
                    let rel = e
                        .path()
                        .strip_prefix(&self.root)
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    out.push(FileEntry {
                        path: rel,
                        size: meta.len(),
                    });
                }
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }

    /// Deletes samples and tmp files older than `max_age`.
    pub fn cleanup(&self, max_age: Duration) {
        for sub in ["samples", "tmp"] {
            let Ok(rd) = std::fs::read_dir(self.root.join(sub)) else {
                continue;
            };
            for e in rd.flatten() {
                let old = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > max_age);
                if old {
                    let _ = if e.path().is_dir() {
                        std::fs::remove_dir_all(e.path())
                    } else {
                        std::fs::remove_file(e.path())
                    };
                }
            }
        }
    }

    /// Isolated interpreter: a venv inside the workspace (no pip, no system site-packages).
    async fn python(&self) -> Result<PathBuf> {
        let venv_py = self.root.join("venv/bin/python3");
        if venv_py.exists() {
            return Ok(venv_py);
        }
        let system = which(&self.cfg.python).with_context(|| {
            format!("python interpreter {:?} not found in PATH", self.cfg.python)
        })?;
        let status = tokio::process::Command::new(&system)
            .args(["-m", "venv", "--without-pip"])
            .arg(self.root.join("venv"))
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        if matches!(status, Ok(s) if s.success()) && venv_py.exists() {
            Ok(venv_py)
        } else {
            tracing::warn!(
                "could not create workspace venv, using {}",
                system.display()
            );
            Ok(system)
        }
    }

    fn read_paths(&self, python: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = [
            "/usr",
            "/lib",
            "/lib64",
            "/lib32",
            "/bin",
            "/sbin",
            "/etc/ld.so.cache",
            "/etc/localtime",
            "/dev/null",
            "/dev/urandom",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        // the real interpreter prefix (e.g. /opt/python3.12) behind the venv symlink
        if let Ok(real) = python.canonicalize()
            && let Some(prefix) = real.parent().and_then(Path::parent)
        {
            v.push(prefix.to_path_buf());
        }
        v.extend(self.cfg.extra_read_paths.iter().cloned());
        v
    }

    pub async fn run_python(&self, script_rel: &str, args: &[String]) -> Result<RunOutput> {
        let script = self.resolve(script_rel)?;
        if !script.starts_with(self.root.join("scripts"))
            || script.extension().is_none_or(|e| e != "py")
        {
            bail!("only .py files under scripts/ can be executed");
        }
        if !script.is_file() {
            bail!("script {script_rel} does not exist");
        }
        if args.len() > 32 || args.iter().any(|a| a.len() > 1024 || a.contains('\0')) {
            bail!("too many or too long arguments");
        }
        let python = self.python().await?;
        let mut cmd = tokio::process::Command::new(&self.launcher);
        cmd.arg("__sandbox-exec")
            .arg("--workspace")
            .arg(&self.root)
            .arg("--memory-mb")
            .arg(self.cfg.memory_mb.to_string())
            .arg("--cpu-secs")
            .arg((self.cfg.timeout_secs + 5).to_string());
        for p in self.read_paths(&python) {
            cmd.arg("--read").arg(p);
        }
        cmd.arg("--")
            .arg(&python)
            .arg("-I")
            .arg("-B")
            .arg(&script)
            .args(args);
        cmd.env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("TMPDIR", self.root.join("tmp"))
            .env("LANG", "C.UTF-8")
            .env("PYTHONIOENCODING", "utf-8")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("MPLCONFIGDIR", self.root.join("cache"))
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);

        let started = Instant::now();
        let mut child = cmd.spawn().context("spawning sandbox launcher")?;
        let pid = child.id();
        let max = self.cfg.max_output_bytes;
        let mut out = child.stdout.take().context("stdout")?;
        let mut err = child.stderr.take().context("stderr")?;
        let read_out = tokio::spawn(async move { read_capped(&mut out, max).await });
        let read_err = tokio::spawn(async move { read_capped(&mut err, max).await });

        let timeout = Duration::from_secs(self.cfg.timeout_secs);
        let (exit_code, timed_out) = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(status) => (status?.code(), false),
            Err(_) => {
                kill_group(pid);
                let _ = child.kill().await;
                (None, true)
            }
        };
        let (stdout, t1) = read_out.await.unwrap_or_default();
        let (stderr, t2) = read_err.await.unwrap_or_default();
        Ok(RunOutput {
            exit_code,
            timed_out,
            duration_ms: started.elapsed().as_millis(),
            stdout: crate::preprocess::redact_long(&stdout),
            stderr: crate::preprocess::redact_long(&stderr),
            truncated: t1 || t2,
        })
    }
}

fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(r: &mut R, max: usize) -> (String, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if buf.len() < max {
                    let take = n.min(max - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                    truncated |= take < n;
                } else {
                    truncated = true; // keep draining so the child never blocks on a full pipe
                }
            }
        }
    }
    (String::from_utf8_lossy(&buf).into_owned(), truncated)
}

#[cfg(unix)]
fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        // SAFETY: killpg only sends a signal; a stale pgid at worst returns ESRCH.
        unsafe {
            libc::killpg(pid as libc::pid_t, libc::SIGKILL);
        }
    }
}
#[cfg(not(unix))]
fn kill_group(_pid: Option<u32>) {}

pub fn which(bin: &str) -> Option<PathBuf> {
    let p = Path::new(bin);
    if p.components().count() > 1 {
        return p.is_file().then(|| p.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(bin))
            .find(|c| c.is_file())
    })
}

// ---------------------------------------------------------------- launcher (child side)

struct LaunchArgs {
    workspace: PathBuf,
    memory_mb: u64,
    cpu_secs: u64,
    read: Vec<PathBuf>,
    probe: bool,
    program: Vec<String>,
}

fn parse_launch(args: &[String]) -> Result<LaunchArgs> {
    let mut la = LaunchArgs {
        workspace: PathBuf::new(),
        memory_mb: 512,
        cpu_secs: 65,
        read: Vec::new(),
        probe: false,
        program: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--workspace" => la.workspace = it.next().context("--workspace value")?.into(),
            "--memory-mb" => la.memory_mb = it.next().context("--memory-mb value")?.parse()?,
            "--cpu-secs" => la.cpu_secs = it.next().context("--cpu-secs value")?.parse()?,
            "--read" => la.read.push(it.next().context("--read value")?.into()),
            "--probe" => la.probe = true,
            "--" => {
                la.program = it.cloned().collect();
                break;
            }
            other => bail!("unknown launcher argument {other}"),
        }
    }
    if !la.probe && (la.program.is_empty() || la.workspace.as_os_str().is_empty()) {
        bail!("usage: __sandbox-exec --workspace DIR [--read DIR]... -- PROGRAM [ARGS]...");
    }
    Ok(la)
}

fn apply_rlimits(la: &LaunchArgs) {
    use rlimit::Resource;
    let mem = la.memory_mb * 1024 * 1024;
    // RLIMIT_AS is not enforced on macOS; RLIMIT_DATA is the closest there
    let _ = if cfg!(target_os = "linux") {
        Resource::AS.set(mem, mem)
    } else {
        Resource::DATA.set(mem, mem)
    };
    let _ = Resource::CPU.set(la.cpu_secs, la.cpu_secs);
    let _ = Resource::FSIZE.set(256 * 1024 * 1024, 256 * 1024 * 1024);
    let _ = Resource::NOFILE.set(256, 256);
    let _ = Resource::CORE.set(0, 0);
    // SAFETY: lowering our own priority has no memory-safety implications.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 10);
    }
}

#[cfg(target_os = "linux")]
fn apply_landlock(la: &LaunchArgs) -> Result<String> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        path_beneath_rules,
    };
    let abi = ABI::V5;
    let read: Vec<&PathBuf> = la.read.iter().filter(|p| p.exists()).collect();
    let mut rw: Vec<&PathBuf> = Vec::new();
    if !la.workspace.as_os_str().is_empty() {
        rw.push(&la.workspace);
    }
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::from_all(abi))?
        .create()?
        .add_rules(path_beneath_rules(read, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(rw, AccessFs::from_all(abi)))?
        .restrict_self()?;
    Ok(match status.ruleset {
        RulesetStatus::FullyEnforced => "fully_enforced",
        RulesetStatus::PartiallyEnforced => "partially_enforced",
        RulesetStatus::NotEnforced => "not_enforced",
    }
    .to_string())
}

#[cfg(not(target_os = "linux"))]
fn apply_landlock(_la: &LaunchArgs) -> Result<String> {
    Ok("unsupported".to_string())
}

/// Entry point of `tsmonitor __sandbox-exec`. Never returns on success (execs the program).
pub fn launcher_main(args: &[String]) -> i32 {
    let la = match parse_launch(args) {
        Ok(la) => la,
        Err(e) => {
            eprintln!("sandbox: {e:#}");
            return 126;
        }
    };
    apply_rlimits(&la);
    let status = match apply_landlock(&la) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sandbox: landlock failed: {e:#}");
            if la.probe {
                println!("{{\"landlock\":\"error\"}}");
                return 0;
            }
            return 126;
        }
    };
    if la.probe {
        println!("{{\"landlock\":\"{status}\"}}");
        return 0;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&la.program[0])
            .args(&la.program[1..])
            .exec();
        eprintln!("sandbox: exec {}: {err}", la.program[0]);
        127
    }
    #[cfg(not(unix))]
    {
        match std::process::Command::new(&la.program[0])
            .args(&la.program[1..])
            .status()
        {
            Ok(s) => s.code().unwrap_or(1),
            Err(e) => {
                eprintln!("sandbox: {e}");
                127
            }
        }
    }
}

/// Reports how strongly the sandbox can be enforced on this host.
pub async fn probe() -> String {
    let Ok(exe) = std::env::current_exe() else {
        return "unknown".into();
    };
    let out = tokio::process::Command::new(exe)
        .args(["__sandbox-exec", "--probe"])
        .stdin(Stdio::null())
        .output()
        .await;
    match out {
        Ok(o) => serde_json::from_slice::<serde_json::Value>(&o.stdout)
            .ok()
            .and_then(|v| {
                v.get("landlock")
                    .and_then(|s| s.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "unknown".into()),
        Err(_) => "unknown".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox(dir: &Path) -> Sandbox {
        let cfg = SandboxConfig {
            timeout_secs: 3,
            max_output_bytes: 1024,
            ..Default::default()
        };
        Sandbox::init(dir, cfg).unwrap()
    }

    #[test]
    fn rejects_escaping_paths() {
        let dir = tempfile::tempdir().unwrap();
        let s = sandbox(dir.path());
        assert_eq!(s.resolve("/etc/passwd"), Err(PathError::Absolute));
        assert_eq!(s.resolve("../x"), Err(PathError::Traversal));
        assert_eq!(s.resolve("scripts/../../x"), Err(PathError::Traversal));
        assert_eq!(s.resolve(""), Err(PathError::Empty));
        assert_eq!(s.resolve("~/x"), Err(PathError::Absolute));
        assert!(s.resolve("scripts/a.py").unwrap().starts_with(s.root()));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let s = sandbox(dir.path());
        std::os::unix::fs::symlink("/etc", s.root().join("samples/etc")).unwrap();
        assert_eq!(s.resolve("samples/etc/passwd"), Err(PathError::Symlink));
        assert!(s.write_file("samples/etc/x", b"x", 10).is_err());
    }

    #[test]
    fn script_names_are_restricted() {
        let dir = tempfile::tempdir().unwrap();
        let s = sandbox(dir.path());
        assert!(s.write_script("../evil.py", "").is_err());
        assert!(s.write_script("ok.sh", "").is_err());
        assert!(s.write_script("ok_1.py", "print(1)").is_ok());
        assert!(
            s.write_script("big.py", &"#".repeat(MAX_SCRIPT_BYTES + 1))
                .is_err()
        );
    }
}
