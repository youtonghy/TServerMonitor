//! Root-owned config of the ops helper (`/etc/tsmonitor/helper.toml`). The daemon cannot change
//! it. Every domain is off unless `enabled = true`, and inside an enabled domain only the
//! operations listed in `allow` may change anything; an enabled domain with an empty `allow`
//! list is read-only.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::ops::proto::DEFAULT_SOCKET;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperConfig {
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
    /// uids allowed to connect besides root (the tsmonitor service user).
    pub allowed_uids: Vec<u32>,
    /// Env var holding the secret the daemon must present (shared via /etc/tsmonitor/env).
    #[serde(default = "default_secret_env")]
    pub secret_env: String,
    /// Backups and pending-change records.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// Log what would happen instead of changing anything.
    #[serde(default)]
    pub dry_run: bool,
    /// Firewall and sshd changes are reverted unless confirmed within this many seconds.
    #[serde(default = "default_confirm_secs")]
    pub confirm_secs: u64,
    #[serde(default)]
    pub docker: DockerDomain,
    #[serde(default)]
    pub nginx: NginxDomain,
    #[serde(default)]
    pub firewall: FirewallDomain,
    #[serde(default)]
    pub ssh: SshDomain,
}

fn default_socket() -> PathBuf {
    DEFAULT_SOCKET.into()
}
fn default_secret_env() -> String {
    "TSM_HELPER_SECRET".into()
}
fn default_state_dir() -> PathBuf {
    "/var/lib/tsmonitor-helper".into()
}
fn default_confirm_secs() -> u64 {
    120
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DockerOp {
    Start,
    Stop,
    Restart,
    Kill,
    Remove,
    ImagePull,
    ImageRemove,
    ImagePrune,
    /// Start / stop / restart every container of a compose project.
    Project,
    VolumeRemove,
    VolumePrune,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerDomain {
    pub enabled: bool,
    /// The real Docker socket (the daemon only ever sees a read-only proxy).
    pub socket: PathBuf,
    pub allow: Vec<DockerOp>,
    /// Container names that may only be started, never stopped, killed or removed.
    /// The socket proxy and TServerMonitor itself are protected automatically.
    pub protected: Vec<String>,
}

impl Default for DockerDomain {
    fn default() -> Self {
        Self {
            enabled: false,
            socket: "/var/run/docker.sock".into(),
            allow: Vec::new(),
            protected: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NginxOp {
    Test,
    Reload,
    /// Enable or disable a site (symlink in sites-enabled, or `.conf` <-> `.conf.disabled`).
    Site,
    /// Write configuration files. ROOT-EQUIVALENT: nginx runs as root while loading config.
    Edit,
    /// Create, change and delete managed sites generated from a form (reverse proxy or
    /// static files). Constrained to the built-in template: static roots must lie under
    /// `site_roots`, and custom directives additionally need `edit`.
    Manage,
    /// Upload certificates and issue / renew them through ACME for managed sites.
    Cert,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeConfig {
    /// Built-in ACME client (HTTP-01). Off by default.
    pub enabled: bool,
    /// Let's Encrypt staging (untrusted test certificates, generous rate limits).
    pub staging: bool,
    /// Another ACME directory (e.g. a private CA); overrides `staging`.
    pub directory: Option<String>,
    /// Root certificate (PEM) of a private ACME directory, for CAs that are not publicly
    /// trusted (step-ca, Pebble).
    pub ca_file: Option<PathBuf>,
    /// Account contact address (optional).
    pub email: Option<String>,
    /// Renew when fewer than this many days are left.
    pub renew_days: u32,
    /// Base URL for the local self-check before an order (default `http://127.0.0.1:<port>`).
    pub preflight_url: Option<String>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            staging: false,
            directory: None,
            ca_file: None,
            email: None,
            renew_days: 30,
            preflight_url: None,
        }
    }
}

impl AcmeConfig {
    pub const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
    pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

    pub fn directory_url(&self) -> &str {
        match &self.directory {
            Some(d) => d,
            None if self.staging => Self::LETSENCRYPT_STAGING,
            None => Self::LETSENCRYPT,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NginxDomain {
    pub enabled: bool,
    pub allow: Vec<NginxOp>,
    pub root: PathBuf,
    /// Directories under `root` whose files may be edited (when `edit` is allowed).
    pub edit_dirs: Vec<String>,
    pub binary: String,
    /// Fetched after every reload; a 5xx, timeout or connection error rolls the change back.
    pub probe_url: Option<String>,
    /// Allowed document roots of managed static sites; missing site directories are created.
    pub site_roots: Vec<String>,
    /// Where existing certificates may be referenced from (`path` SSL mode).
    pub cert_paths: Vec<String>,
    pub acme: AcmeConfig,
}

impl Default for NginxDomain {
    fn default() -> Self {
        Self {
            enabled: false,
            allow: Vec::new(),
            root: "/etc/nginx".into(),
            edit_dirs: vec!["conf.d".into(), "sites-available".into(), "snippets".into()],
            binary: "nginx".into(),
            probe_url: None,
            site_roots: vec!["/var/www".into()],
            cert_paths: vec!["/etc/letsencrypt".into(), "/etc/ssl".into()],
            acme: AcmeConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    Ufw,
    Firewalld,
    Nftables,
    Iptables,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallOp {
    AddRule,
    DeleteRule,
    /// ufw enable / disable.
    Toggle,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallDomain {
    pub enabled: bool,
    /// Detected when omitted (ufw, then firewalld, then nftables, then iptables).
    pub backend: Option<FirewallBackend>,
    pub allow: Vec<FirewallOp>,
    /// firewalld zone; the default zone when omitted.
    pub zone: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshOp {
    /// Change sshd options through a drop-in file.
    Options,
    KeyAdd,
    KeyRemove,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshDomain {
    pub enabled: bool,
    pub allow: Vec<SshOp>,
    /// Drop-in written by the helper; `sshd_config` must include `sshd_config.d/*.conf`.
    pub dropin: PathBuf,
    pub sshd_config: PathBuf,
    pub sshd_binary: String,
}

impl Default for SshDomain {
    fn default() -> Self {
        Self {
            enabled: false,
            allow: Vec::new(),
            dropin: "/etc/ssh/sshd_config.d/00-tsmonitor.conf".into(),
            sshd_config: "/etc/ssh/sshd_config".into(),
            sshd_binary: "sshd".into(),
        }
    }
}

impl HelperConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: HelperConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if !(15..=900).contains(&self.confirm_secs) {
            bail!("confirm_secs must be between 15 and 900");
        }
        for d in &self.nginx.edit_dirs {
            crate::ops::validate::file_name(d)
                .map_err(|e| anyhow::anyhow!("nginx.edit_dirs: {e}"))?;
            if d == crate::ops::nginx_site::OWN_DIR {
                bail!("nginx.edit_dirs must not contain the helper's own directory {d:?}");
            }
        }
        for (what, list) in [
            ("site_roots", &self.nginx.site_roots),
            ("cert_paths", &self.nginx.cert_paths),
        ] {
            for p in list {
                let n = crate::ops::nginx_site::abs_path(what, p)
                    .map_err(|e| anyhow::anyhow!("nginx.{what}: {e}"))?;
                if n.matches('/').count() < 2 && what == "site_roots" {
                    bail!("nginx.site_roots entries must be at least two levels deep: {p:?}");
                }
            }
        }
        if let Some(d) = &self.nginx.acme.directory {
            let p = url::Url::parse(d).context("nginx.acme.directory")?;
            if p.scheme() != "https" {
                bail!("nginx.acme.directory must be https");
            }
        }
        if let Some(e) = &self.nginx.acme.email
            && (e.contains(char::is_whitespace) || !e.contains('@'))
        {
            bail!("nginx.acme.email is not an e-mail address");
        }
        if !(1..=60).contains(&self.nginx.acme.renew_days) {
            bail!("nginx.acme.renew_days must be between 1 and 60");
        }
        if let Some(z) = &self.firewall.zone {
            crate::ops::validate::simple_name("zone", z)
                .map_err(|e| anyhow::anyhow!("firewall.zone: {e}"))?;
        }
        if let Some(u) = &self.nginx.probe_url {
            let p = url::Url::parse(u).context("nginx.probe_url")?;
            if !matches!(p.scheme(), "http" | "https") {
                bail!("nginx.probe_url must be http(s)");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_is_read_only_by_default() {
        let c: HelperConfig =
            toml::from_str(include_str!("../../../deploy/helper.example.toml")).unwrap();
        c.validate().unwrap();
        assert!(c.dry_run);
        assert!(!c.docker.enabled && !c.nginx.enabled && !c.firewall.enabled && !c.ssh.enabled);
        assert!(c.docker.allow.is_empty() && c.nginx.allow.is_empty());
    }

    #[test]
    fn minimal_config_has_everything_off() {
        let c: HelperConfig = toml::from_str("allowed_uids = [999]").unwrap();
        assert!(!c.docker.enabled && !c.ssh.enabled);
        assert_eq!(c.confirm_secs, 120);
        assert!(toml::from_str::<HelperConfig>("allowed_uids = []\nbogus = 1").is_err());
    }
}
