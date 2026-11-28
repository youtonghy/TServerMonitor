//! Wire types shared by the HTTP API, SSE, MCP, webhooks and the AI sidecar.
//! Keep in sync with `docs/api.md`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskUsage {
    pub mount: String,
    pub fs: String,
    pub used: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetIf {
    pub name: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostMetrics {
    pub ts: i64,
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub uptime_secs: u64,
    pub cpu_pct: f64,
    pub cpu_cores: usize,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub mem_used: u64,
    pub mem_total: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub disk_read_bps: f64,
    pub disk_write_bps: f64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
    pub disks: Vec<DiskUsage>,
    pub nets: Vec<NetIf>,
}

impl HostMetrics {
    pub fn mem_pct(&self) -> f64 {
        pct(self.mem_used, self.mem_total)
    }
    pub fn swap_pct(&self) -> f64 {
        pct(self.swap_used, self.swap_total)
    }
    /// Fullest mounted filesystem.
    pub fn disk_pct(&self) -> f64 {
        self.disks
            .iter()
            .map(|d| pct(d.used, d.total))
            .fold(0.0, f64::max)
    }
}

pub fn pct(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 * 100.0 / total as f64
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default, PartialEq)]
pub struct HealthDimensions {
    pub cpu: f64,
    pub memory: f64,
    pub disk: f64,
    pub logs: f64,
    pub security: f64,
    pub containers: f64,
    pub database: f64,
}

impl HealthDimensions {
    pub fn clamp(mut self) -> Self {
        for v in [
            &mut self.cpu,
            &mut self.memory,
            &mut self.disk,
            &mut self.logs,
            &mut self.security,
            &mut self.containers,
            &mut self.database,
        ] {
            *v = v.clamp(0.0, 100.0).round();
        }
        self
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Normal,
    HighLog,
    IdleAudit,
    Yield,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeState {
    pub mode: Mode,
    pub reason: String,
    pub since: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiStatus {
    pub enabled: bool,
    pub reason: Option<String>,
    pub format: Option<crate::config::ApiFormat>,
    pub model: Option<String>,
    pub runs_today: u32,
    pub daily_budget: u32,
    pub running: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub score: f64,
    pub dimensions: HealthDimensions,
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerSummary {
    pub total: usize,
    pub running: usize,
    pub unhealthy: usize,
    pub restart_loops: usize,
    pub oom: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertCounts {
    pub critical: i64,
    pub warning: i64,
    pub info: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub generated_at: i64,
    pub host: Option<HostMetrics>,
    pub health: Health,
    pub mode: ModeState,
    pub containers: ContainerSummary,
    pub alerts_open: AlertCounts,
    pub ai: AiStatus,
    pub latest_report: Option<ReportSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub ts: i64,
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub swap_pct: f64,
    pub disk_pct: f64,
    pub load1: f64,
    pub disk_read_bps: f64,
    pub disk_write_bps: f64,
    pub net_rx_bps: f64,
    pub net_tx_bps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPoint {
    pub ts: i64,
    pub cpu_pct: f64,
    pub mem_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub health: Option<String>,
    pub restart_count: i64,
    pub restart_loop: bool,
    pub oom_killed: bool,
    pub cpu_pct: f64,
    pub mem_used: u64,
    pub mem_limit: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub started_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<ContainerPoint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSourceInfo {
    pub name: String,
    pub kind: String,
    pub path: Option<String>,
    pub container: Option<String>,
    pub lines_total: u64,
    pub errors_total: u64,
    pub rate_per_min: f64,
    pub errors_per_min: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LogCluster {
    pub fingerprint: String,
    pub source: String,
    pub level: String,
    pub template: String,
    pub sample: String,
    pub count: i64,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Finding {
    pub id: i64,
    pub category: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub evidence: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub proto: &'static str,
    pub addr: String,
    pub port: u16,
    pub process: Option<String>,
    pub exposed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStatus {
    pub name: String,
    pub kind: crate::config::DbKind,
    pub ok: bool,
    pub error: Option<String>,
    pub metrics: std::collections::BTreeMap<String, f64>,
    pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Alert {
    pub id: i64,
    pub severity: String,
    pub source: String,
    pub title: String,
    pub summary: String,
    pub suggestion: Option<String>,
    pub fingerprint: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub count: i64,
    pub status: String,
    pub notified: bool,
    pub acked_at: Option<i64>,
    pub silenced_until: Option<i64>,
}

// ---- AI diagnosis (also the structured-output schema handed to the model) ----

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RecCategory {
    Code,
    Config,
    Infra,
    Database,
    Security,
}

#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RootCause {
    pub title: String,
    pub evidence: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecurityRisk {
    pub title: String,
    pub severity: FindingSeverity,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Recommendation {
    pub title: String,
    pub category: RecCategory,
    pub priority: Priority,
    pub detail: String,
    pub expected_impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Anomaly {
    pub title: String,
    pub detail: String,
    pub severity: AlertSeverity,
}

/// Structured diagnosis produced by the AI (or by the rules fallback).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Diagnosis {
    /// Overall health 0-100, higher is healthier.
    pub health_score: f64,
    /// Chinese summary for the operator, in Markdown: a one-sentence conclusion first, then short
    /// `- ` bullet lists under `**粗体小标题**` (现状 / 待关注 / 建议), key numbers in `**bold**`,
    /// identifiers in `code`. No headings, tables, links or HTML; at most about 12 lines.
    pub summary: String,
    /// Per-dimension health 0-100.
    pub dimensions: HealthDimensions,
    pub root_causes: Vec<RootCause>,
    pub security_risks: Vec<SecurityRisk>,
    pub recommendations: Vec<Recommendation>,
    pub anomalies: Vec<Anomaly>,
}

impl Diagnosis {
    pub fn normalized(mut self) -> Self {
        self.health_score = self.health_score.clamp(0.0, 100.0).round();
        self.dimensions = self.dimensions.clamp();
        self.recommendations.sort_by_key(|r| r.priority);
        self
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ReportKind {
    Hourly,
    Daily,
    Incident,
    Audit,
    /// A user-configured task from `scheduled_tasks`.
    Custom,
}

impl ReportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hourly => "hourly",
            Self::Daily => "daily",
            Self::Incident => "incident",
            Self::Audit => "audit",
            Self::Custom => "custom",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "hourly" => Some(Self::Hourly),
            "daily" => Some(Self::Daily),
            "incident" => Some(Self::Incident),
            "audit" => Some(Self::Audit),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Hourly => "小时巡检",
            Self::Daily => "每日运维简报",
            Self::Incident => "异常事件分析",
            Self::Audit => "深度审计",
            Self::Custom => "自定义任务",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReportSummary {
    pub id: i64,
    pub kind: String,
    pub created_at: i64,
    pub health_score: f64,
    pub title: String,
    pub summary: String,
    pub generated_by: String,
    pub model: Option<String>,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub summary: ReportSummary,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AgentRun {
    pub id: String,
    pub trigger: String,
    pub kind: String,
    pub status: String,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub model: Option<String>,
    pub steps_count: i64,
    pub error: Option<String>,
    pub report_id: Option<i64>,
    pub conversation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Conversation {
    pub id: String,
    pub title: String,
    /// "chat" or the task kind of the run that created it.
    pub kind: String,
    #[sqlx(json(nullable))]
    pub context: Option<serde_json::Value>,
    pub created_at: i64,
    pub updated_at: i64,
    /// Status of the newest run.
    pub last_status: Option<String>,
    pub runs: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStep {
    pub seq: i64,
    pub ts: i64,
    pub kind: String,
    pub tool: Option<String>,
    pub input: Option<serde_json::Value>,
    pub output: Option<serde_json::Value>,
    pub text: Option<String>,
}

/// Events fanned out over SSE.
#[derive(Debug, Clone)]
pub enum Event {
    Metrics(Box<HostMetrics>),
    Containers(Vec<ContainerInfo>),
    Alert(Alert),
    Mode(ModeState),
    Agent {
        run_id: String,
        conversation_id: Option<String>,
        status: String,
        step: Option<AgentStep>,
    },
    /// Streamed text of an interactive run; not persisted (the final text arrives as a step).
    AgentDelta {
        run_id: String,
        conversation_id: String,
        text: String,
    },
    Report(ReportSummary),
    /// Package update job progress: a log line, or a status change when `line` is None.
    PackageJob {
        id: i64,
        status: String,
        line: Option<String>,
    },
    /// Ops helper job progress: a log line, or a status change when `line` is None.
    OpsJob {
        id: i64,
        status: String,
        line: Option<String>,
    },
    /// Changes waiting for confirmation (the full current list).
    OpsPending(serde_json::Value),
    /// A change request was filed or changed state (see `approvals`).
    Approval {
        id: i64,
        status: String,
    },
    /// Runtime settings changed; carries no secrets.
    Settings {
        generation: u64,
    },
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Metrics(_) => "metrics",
            Self::Containers(_) => "containers",
            Self::Alert(_) => "alert",
            Self::Mode(_) => "mode",
            Self::Agent { .. } => "agent",
            Self::AgentDelta { .. } => "agent_delta",
            Self::Report(_) => "report",
            Self::Settings { .. } => "settings",
            Self::PackageJob { .. } => "package_job",
            Self::OpsJob { .. } => "ops_job",
            Self::OpsPending(_) => "ops_pending",
            Self::Approval { .. } => "approval",
        }
    }

    pub fn data(&self) -> serde_json::Value {
        match self {
            Self::Metrics(m) => serde_json::to_value(m),
            Self::Containers(c) => serde_json::to_value(c),
            Self::Alert(a) => serde_json::to_value(a),
            Self::Mode(m) => serde_json::to_value(m),
            Self::Agent {
                run_id,
                conversation_id,
                status,
                step,
            } => Ok(
                serde_json::json!({ "run_id": run_id, "conversation_id": conversation_id, "status": status, "step": step }),
            ),
            Self::AgentDelta {
                run_id,
                conversation_id,
                text,
            } => Ok(
                serde_json::json!({ "run_id": run_id, "conversation_id": conversation_id, "text": text }),
            ),
            Self::Report(r) => serde_json::to_value(r),
            Self::Settings { generation } => Ok(serde_json::json!({ "generation": generation })),
            Self::PackageJob { id, status, line } | Self::OpsJob { id, status, line } => {
                Ok(serde_json::json!({ "id": id, "status": status, "line": line }))
            }
            Self::OpsPending(v) => Ok(v.clone()),
            Self::Approval { id, status } => Ok(serde_json::json!({ "id": id, "status": status })),
        }
        .unwrap_or(serde_json::Value::Null)
    }
}
