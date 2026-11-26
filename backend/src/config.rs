//! Configuration: non-secret settings come from `config.toml`, secrets only from environment variables.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub collect: CollectConfig,
    pub docker: DockerConfig,
    pub logs: Vec<LogSourceConfig>,
    pub security: SecurityConfig,
    pub databases: Vec<DatabaseConfig>,
    pub schedule: ScheduleConfig,
    pub thresholds: Thresholds,
    pub ai: AiConfig,
    pub sandbox: SandboxConfig,
    pub notify: NotifyConfig,
    pub packages: PackagesConfig,
    pub ops: OpsConfig,
}

/// Management through the optional root ops helper (`tsmonitor helper`). What the helper may
/// actually do is decided by its own root-owned config, not here.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpsConfig {
    pub helper_socket: PathBuf,
    /// Env var with the secret shared with the helper (same value in both units' env).
    pub secret_env: String,
    /// Allow changes even when the analysis-script sandbox has no kernel isolation. Without
    /// isolation an AI-written script running as the daemon user could try to reach the helper.
    pub allow_without_sandbox: bool,
    /// Used for read-only views when the helper is not running.
    pub nginx_root: PathBuf,
    pub sshd_config: PathBuf,
}

impl Default for OpsConfig {
    fn default() -> Self {
        Self {
            helper_socket: crate::ops::proto::DEFAULT_SOCKET.into(),
            secret_env: "TSM_HELPER_SECRET".into(),
            allow_without_sandbox: false,
            nginx_root: "/etc/nginx".into(),
            sshd_config: "/etc/ssh/sshd_config".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackagesConfig {
    /// Socket of the optional root update helper (`tsmonitor updater`). Updates can only be
    /// applied from the dashboard when the helper is installed and listening here.
    pub updater_socket: PathBuf,
}

impl Default for PackagesConfig {
    fn default() -> Self {
        Self {
            updater_socket: crate::updater::DEFAULT_SOCKET.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    /// Name of the env var holding the API bearer token.
    pub token_env: String,
    /// Name of the env var holding the separate ops token. Changes to nginx, the firewall, SSH
    /// and Docker (web and MCP) require it in the `X-TSM-Ops-Token` header, never in a URL.
    pub ops_token_env: String,
    /// Extra `Host` values accepted by the MCP endpoint (loopback is always accepted), e.g.
    /// `["monitor.example.com"]` when an agent connects through a reverse proxy.
    pub mcp_allowed_hosts: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8787".parse().expect("valid default addr"),
            token_env: "TSM_API_TOKEN".into(),
            ops_token_env: "TSM_OPS_TOKEN".into(),
            mcp_allowed_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub raw_retention_days: i64,
    pub rollup_retention_days: i64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            raw_retention_days: 7,
            rollup_retention_days: 90,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CollectConfig {
    pub interval_secs: u64,
    pub container_interval_secs: u64,
    /// Log files are polled for new lines this often.
    pub log_poll_secs: u64,
}

impl Default for CollectConfig {
    fn default() -> Self {
        Self {
            interval_secs: 10,
            container_interval_secs: 15,
            log_poll_secs: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerConfig {
    pub enabled: bool,
    /// Follow container stdout/stderr for error lines.
    pub follow_logs: bool,
    /// Maximum log lines pulled per container per poll.
    pub max_log_lines: usize,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            follow_logs: true,
            max_log_lines: 500,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogKind {
    PhpError,
    PhpSlow,
    NginxAccess,
    NginxError,
    Node,
    MysqlSlow,
    Generic,
    Docker,
}

impl LogKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PhpError => "php_error",
            Self::PhpSlow => "php_slow",
            Self::NginxAccess => "nginx_access",
            Self::NginxError => "nginx_error",
            Self::Node => "node",
            Self::MysqlSlow => "mysql_slow",
            Self::Generic => "generic",
            Self::Docker => "docker",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSourceConfig {
    pub name: String,
    pub path: PathBuf,
    pub kind: LogKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    /// Auto-detected (/var/log/auth.log or /var/log/secure) when empty.
    pub auth_log: Option<PathBuf>,
    pub failed_login_threshold: u32,
    pub check_updates: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 900,
            auth_log: None,
            failed_login_threshold: 20,
            check_updates: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DbKind {
    Mysql,
    Postgres,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub name: String,
    pub kind: DbKind,
    /// Env var holding the DSN of a read-only account.
    pub dsn_env: String,
    #[serde(default = "default_db_interval")]
    pub interval_secs: u64,
}

fn default_db_interval() -> u64 {
    60
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScheduleConfig {
    pub hourly: bool,
    /// Local time "HH:MM" for the daily report.
    pub daily_at: String,
    /// Error rate must exceed baseline * burst_factor to count as a burst.
    pub burst_factor: f64,
    /// ...and at least this many errors per minute.
    pub burst_min_errors_per_min: f64,
    pub burst_cooldown_mins: i64,
    /// Local time window "HH:MM-HH:MM" considered a quiet period for deep audits.
    pub idle_window: String,
    pub idle_cpu_pct: f64,
    /// Host is considered busy above these values; deep work is postponed.
    pub yield_cpu_pct: f64,
    pub yield_load_per_core: f64,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            hourly: true,
            daily_at: "04:00".into(),
            burst_factor: 3.0,
            burst_min_errors_per_min: 20.0,
            burst_cooldown_mins: 15,
            idle_window: "01:00-05:00".into(),
            idle_cpu_pct: 30.0,
            yield_cpu_pct: 85.0,
            yield_load_per_core: 1.5,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Thresholds {
    pub cpu_warn: f64,
    pub cpu_crit: f64,
    pub mem_warn: f64,
    pub mem_crit: f64,
    pub swap_warn: f64,
    pub disk_warn: f64,
    pub disk_crit: f64,
    /// Consecutive samples over a threshold before an alert fires.
    pub sustain_samples: u32,
    pub alert_cooldown_mins: i64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            cpu_warn: 85.0,
            cpu_crit: 95.0,
            mem_warn: 85.0,
            mem_crit: 95.0,
            swap_warn: 50.0,
            disk_warn: 85.0,
            disk_crit: 95.0,
            sustain_samples: 6,
            alert_cooldown_mins: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiFormat {
    /// OpenAI Responses API (`POST {base_url}/responses`).
    Responses,
    /// Anthropic Messages API (`POST {base_url}/messages`).
    Messages,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelProfile {
    pub api_format: ApiFormat,
    pub base_url: String,
    pub model: String,
    #[serde(default = "default_key_env")]
    pub api_key_env: String,
    /// How the key is sent for `messages`: `x-api-key` header (default) or `Authorization: Bearer`
    /// (some relays require it). `responses` always uses Bearer.
    #[serde(default)]
    pub auth: AuthStyle,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthStyle {
    #[default]
    ApiKey,
    Bearer,
}

fn default_key_env() -> String {
    "TSM_LLM_API_KEY".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    pub enabled: bool,
    pub node_bin: String,
    /// Override for the sidecar script; the embedded copy is used when empty.
    pub sidecar_path: Option<PathBuf>,
    pub daily_budget: u32,
    pub max_steps: u32,
    pub timeout_secs: u64,
    pub idle_exit_secs: u64,
    pub profiles: BTreeMap<String, ModelProfile>,
    /// Report kind -> profile name. Kinds without an entry use "default".
    pub routing: BTreeMap<String, String>,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            node_bin: "node".into(),
            sidecar_path: None,
            daily_budget: 200,
            max_steps: 12,
            timeout_secs: 300,
            idle_exit_secs: 300,
            profiles: BTreeMap::new(),
            routing: BTreeMap::new(),
        }
    }
}

impl AiConfig {
    pub fn profile_for(&self, kind: &str) -> Option<(&str, &ModelProfile)> {
        let name = self
            .routing
            .get(kind)
            .map(String::as_str)
            .unwrap_or("default");
        self.profiles
            .get_key_value(name)
            .map(|(k, v)| (k.as_str(), v))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub python: String,
    pub timeout_secs: u64,
    pub max_output_bytes: usize,
    pub memory_mb: u64,
    /// Extra read-only paths for the Python process (e.g. a pyenv install).
    pub extra_read_paths: Vec<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            python: "python3".into(),
            timeout_secs: 60,
            max_output_bytes: 64 * 1024,
            memory_mb: 512,
            extra_read_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    pub telegram: TelegramConfig,
    pub webhooks: Vec<WebhookConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "critical" => Self::Critical,
            "warning" => Self::Warning,
            _ => Self::Info,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub chat_id: String,
    pub token_env: String,
    /// Alerts at or above this severity are pushed immediately.
    pub min_severity: Severity,
    pub send_daily_report: bool,
    /// Hourly digest of warnings that were not pushed immediately.
    pub warning_digest: bool,
    pub api_base: String,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            chat_id: String::new(),
            token_env: "TSM_TELEGRAM_BOT_TOKEN".into(),
            min_severity: Severity::Critical,
            send_daily_report: true,
            warning_digest: true,
            api_base: "https://api.telegram.org".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub secret_env: Option<String>,
    #[serde(default = "default_webhook_events")]
    pub events: Vec<String>,
}

fn default_webhook_events() -> Vec<String> {
    vec!["alert".into(), "report".into()]
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.server.bind.ip().is_loopback()
            && std::env::var(&self.server.token_env)
                .unwrap_or_default()
                .is_empty()
        {
            bail!(
                "server.bind is {} (not loopback) but {} is not set; refusing to expose the dashboard without a token",
                self.server.bind,
                self.server.token_env
            );
        }
        if let Some(ops) = secret(&self.server.ops_token_env) {
            if ops.len() < 16 {
                bail!(
                    "{} must be at least 16 characters",
                    self.server.ops_token_env
                );
            }
            if secret(&self.server.token_env).as_deref() == Some(ops.as_str()) {
                bail!(
                    "{} must differ from {}",
                    self.server.ops_token_env,
                    self.server.token_env
                );
            }
        }
        parse_hhmm(&self.schedule.daily_at).context("schedule.daily_at")?;
        parse_window(&self.schedule.idle_window).context("schedule.idle_window")?;
        let mut names = std::collections::HashSet::new();
        for l in &self.logs {
            if !names.insert(l.name.as_str()) {
                bail!("duplicate log source name {}", l.name);
            }
        }
        for (kind, profile) in &self.ai.routing {
            if !self.ai.profiles.contains_key(profile) {
                bail!("ai.routing.{kind} points to unknown profile {profile}");
            }
        }
        if self.collect.interval_secs == 0
            || self.collect.container_interval_secs == 0
            || self.collect.log_poll_secs == 0
        {
            bail!("collect intervals must be > 0");
        }
        Ok(())
    }
}

pub fn parse_hhmm(s: &str) -> Result<chrono::NaiveTime> {
    chrono::NaiveTime::parse_from_str(s.trim(), "%H:%M")
        .with_context(|| format!("expected HH:MM, got {s:?}"))
}

pub fn parse_window(s: &str) -> Result<(chrono::NaiveTime, chrono::NaiveTime)> {
    let (a, b) = s
        .split_once('-')
        .with_context(|| format!("expected HH:MM-HH:MM, got {s:?}"))?;
    Ok((parse_hhmm(a)?, parse_hhmm(b)?))
}

/// Reads a secret from the environment. Empty values count as missing.
pub fn secret(env: &str) -> Option<String> {
    std::env::var(env).ok().filter(|v| !v.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../deploy/config.example.toml");
        let cfg: Config = toml::from_str(text).expect("example config parses");
        cfg.validate().expect("example config is valid");
        assert!(cfg.ai.profile_for("daily").is_some());
    }

    #[test]
    fn window_parses() {
        let (a, b) = parse_window("23:00-05:30").unwrap();
        assert!(a > b);
    }
}
