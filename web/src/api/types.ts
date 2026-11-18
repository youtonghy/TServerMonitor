// Mirrors docs/api.md exactly. Timestamps are Unix epoch milliseconds, byte counts are bytes,
// rates are per second unless the field name says otherwise.

export type Severity = "info" | "warning" | "critical"; // alerts
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type Mode = "normal" | "high_log" | "idle_audit" | "yield";

export interface DiskUsage { mount: string; fs: string; used: number; total: number }
export interface NetIf { name: string; rx_bps: number; tx_bps: number }

export interface HostMetrics {
  ts: number; hostname: string; os: string; kernel: string; uptime_secs: number;
  cpu_pct: number; cpu_cores: number; load1: number; load5: number; load15: number;
  mem_used: number; mem_total: number; swap_used: number; swap_total: number;
  disk_read_bps: number; disk_write_bps: number; net_rx_bps: number; net_tx_bps: number;
  disks: DiskUsage[]; nets: NetIf[];
}

export interface HealthDimensions {
  cpu: number; memory: number; disk: number; logs: number;
  security: number; containers: number; database: number; // each 0-100, higher is healthier
}

export interface ModeState { mode: Mode; reason: string; since: number }

export interface Snapshot {
  generated_at: number;
  host: HostMetrics | null; // null until the first sample
  health: { score: number; dimensions: HealthDimensions; source: "ai" | "rules" };
  mode: ModeState;
  containers: { total: number; running: number; unhealthy: number; restart_loops: number; oom: number };
  alerts_open: { critical: number; warning: number; info: number };
  ai: AiStatus;
  latest_report: ReportSummary | null;
}

export interface AiStatus {
  enabled: boolean; reason: string | null; // reason is set when disabled
  format: "responses" | "messages" | null; model: string | null;
  runs_today: number; daily_budget: number; running: string | null; // running = run id
}

export interface MetricPoint {
  ts: number; cpu_pct: number; mem_pct: number; swap_pct: number; disk_pct: number;
  load1: number; disk_read_bps: number; disk_write_bps: number; net_rx_bps: number; net_tx_bps: number;
}

export interface ContainerSample { ts: number; cpu_pct: number; mem_used: number }

export interface ContainerInfo {
  id: string; name: string; image: string;
  state: string; // running | exited | restarting | paused | created | dead
  status: string; // docker human status, e.g. "Up 3 hours"
  health: string | null; // healthy | unhealthy | starting | null
  restart_count: number; restart_loop: boolean; oom_killed: boolean;
  cpu_pct: number; mem_used: number; mem_limit: number; net_rx: number; net_tx: number;
  started_at: number | null;
  history: ContainerSample[]; // last 60 samples
}

export interface LogSource {
  name: string; kind: string; // php_error | php_slow | nginx_access | nginx_error | node | mysql_slow | generic | docker
  path: string | null; container: string | null;
  lines_total: number; errors_total: number; rate_per_min: number; errors_per_min: number;
}

export interface LogCluster {
  fingerprint: string; source: string; level: string; // error | warning | info | slow
  template: string; sample: string; count: number; first_seen: number; last_seen: number;
}

export interface Finding {
  id: number; category: string; // port | login | update | kernel | network | db | container | config
  severity: FindingSeverity; title: string; detail: string; evidence: string;
  first_seen: number; last_seen: number; resolved: boolean;
}

export interface Alert {
  id: number; severity: Severity; source: string; title: string; summary: string;
  suggestion: string | null; fingerprint: string; created_at: number; last_seen: number;
  count: number; status: "open" | "resolved"; notified: boolean;
  /** Acknowledged alerts are only notified again when they escalate. */
  acked_at: number | null;
  /** No notifications until this time (also for new alerts with the same fingerprint). */
  silenced_until: number | null;
}

export type Confidence = "low" | "medium" | "high";
export type RecommendationCategory = "code" | "config" | "infra" | "database" | "security";
export type Priority = "high" | "medium" | "low";

export interface Diagnosis {
  health_score: number; summary: string; dimensions: HealthDimensions;
  root_causes: { title: string; evidence: string; confidence: Confidence }[];
  security_risks: { title: string; severity: FindingSeverity; detail: string; recommendation: string }[];
  recommendations: {
    title: string; category: RecommendationCategory;
    priority: Priority; detail: string; expected_impact: string;
  }[];
  anomalies: { title: string; detail: string; severity: Severity }[];
}

export type ReportKind = "hourly" | "daily" | "incident" | "audit" | "custom";
export interface ReportSummary {
  id: number; kind: ReportKind; created_at: number; health_score: number;
  title: string; summary: string; generated_by: "ai" | "rules"; model: string | null; run_id: string | null;
}
export interface Report extends ReportSummary { body: Diagnosis }

export type AgentRunStatus = "running" | "succeeded" | "failed" | "fallback" | "cancelled";
/** Report kinds for scheduled analyses, "chat" for a conversation turn. */
export type RunKind = ReportKind | "chat";
export interface AgentRun {
  id: string; trigger: string; kind: RunKind;
  status: AgentRunStatus;
  started_at: number; finished_at: number | null; model: string | null;
  steps_count: number; error: string | null; report_id: number | null;
  conversation_id: string | null;
}
export interface AgentStep {
  seq: number; ts: number; kind: "user" | "tool_call" | "tool_result" | "message" | "error";
  tool: string | null; input: unknown | null; output: unknown | null; text: string | null;
}
export type AgentRunDetail = AgentRun & { steps: AgentStep[] };

export type ConversationContext = { report_id: number } | { alert_id: number } | { run_id: string } | { text: string };
export interface Conversation {
  id: string; title: string;
  /** "chat" for user conversations, otherwise the kind of the scheduled run that created it. */
  kind: RunKind;
  context: ConversationContext | null;
  created_at: number; updated_at: number;
  last_status: AgentRunStatus | null; runs: number;
}
export type ConversationDetail = Omit<Conversation, "runs"> & { runs: AgentRunDetail[] };
export interface NewConversation { title?: string; context?: ConversationContext; message?: string }

// Endpoint payloads

export type MetricsRange = "1h" | "6h" | "24h" | "7d" | "30d";

export interface StatusResponse {
  version: string; platform: string; started_at: number; mode: ModeState; ai: AiStatus;
  collectors: Record<string, { ok: boolean; detail: string | null }>;
}

export interface MetricsResponse { step_secs: number; points: MetricPoint[] }

export interface ContainerLogLine { ts: number | null; stream: "stdout" | "stderr"; text: string }
export interface ContainerLogsResponse { lines: ContainerLogLine[] }

export interface LogRatesResponse {
  step_secs: number;
  series: { source: string; points: { ts: number; lines: number; errors: number }[] }[];
}

export interface DailyErrorCount { date: string; count: number } // date is YYYY-MM-DD

export interface PortInfo { proto: "tcp" | "udp"; addr: string; port: number; process: string | null; exposed: boolean }

export interface DbStatus {
  name: string; kind: "mysql" | "postgres"; ok: boolean; error: string | null;
  metrics: Record<string, number>; ts: number;
}

export interface TriggerResponse { run_id: string }

// Settings

export type ApiFormat = "responses" | "messages";
export type AuthStyle = "api_key" | "bearer";
export type Effort = "" | "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
export type KeyStorage = "env" | "file" | "unavailable";

export interface Provider {
  id: string; name: string;
  /** "db" providers are editable; "config" ones come from config.toml. */
  source: "db" | "config";
  api_format: ApiFormat; base_url: string; auth: AuthStyle; default_model: string;
  has_key: boolean; key_env?: string; updated_at: number | null;
}
export interface ProvidersResponse { providers: Provider[]; key_storage: KeyStorage }

export interface ProviderInput {
  name?: string; api_format?: ApiFormat; base_url?: string; auth?: AuthStyle; default_model?: string;
  /** Write-only; empty string clears the stored key. */
  api_key?: string;
}

export interface ModelsRequest {
  provider_id?: string; api_format?: ApiFormat; base_url?: string; auth?: AuthStyle; api_key?: string;
}

export interface Route { kind: string; provider: string; model: string; effort: Effort }
export interface ResolvedModel { provider: string; source: "db" | "config"; api_format: ApiFormat; base_url: string; model: string; auth: AuthStyle; effort: Effort }
export interface RoutingResponse {
  kinds: { kind: string; label: string; resolved: ResolvedModel | null }[];
  efforts: Effort[];
  routes: Route[];
}

// Automated tasks and the prompt library

export type Trigger =
  | { type: "interval"; every_mins: number }
  | { type: "daily"; at: string }
  | { type: "log_threshold"; source: string | null; metric: "lines" | "errors"; count: number; min_interval_mins: number }
  | { type: "burst" }
  | { type: "manual" };
export interface Task {
  id: string; name: string; enabled: boolean; builtin: boolean; trigger: Trigger;
  prompt_id: string; route_kind: string;
  last_fired_at: number | null; cursor: number | null; last_run_id: string | null;
  created_at: number; updated_at: number;
}
/** Fixed jobs from [schedule] in config.toml, read-only. */
export interface SystemJob { id: string; name: string; enabled: boolean; trigger: string; prompt_id: string; route_kind: string }
export interface TasksResponse { tasks: Task[]; system: SystemJob[] }
export interface TaskInput { name?: string; enabled?: boolean; trigger?: Trigger; prompt_id?: string; route_kind?: string }

export interface Prompt {
  id: string; name: string; description: string; body: string;
  /** Built-in prompts ship with the program and are read-only. */
  builtin: boolean; route_kind: string; updated_at: number | null;
}
export interface PromptInput { name?: string; description?: string; body?: string }

// Real-time access analysis (nginx access logs)

export interface AccessStats {
  window_mins: number; requests: number; requests_per_min: number;
  /** [2xx, 3xx, 4xx, 5xx] */
  status: [number, number, number, number];
  error_rate_5xx: number; bytes: number;
  series: { ts: number; requests: number; s4xx: number; s5xx: number }[];
  top_paths: { path: string; requests: number; s5xx: number }[];
  top_ips: { ip: string; requests: number }[];
}
export interface AccessResponse { sources: string[]; stats: AccessStats }

// Notification channels

export type ChannelKind = "telegram" | "email" | "webhook";
export type ChannelEvent = "alert" | "report" | "digest";
export interface TelegramConfig { chat_id: string; api_base: string; bot_enabled: boolean; allowed_user_ids: number[] }
export interface EmailConfig { host: string; port: number; security: "starttls" | "tls" | "none"; username: string; from: string; to: string[] }
export interface WebhookChannelConfig { url: string }
export interface NotifyChannel {
  id: string; name: string; kind: ChannelKind; source: "db" | "config"; enabled: boolean;
  min_severity: Severity; events: ChannelEvent[];
  config: TelegramConfig | EmailConfig | WebhookChannelConfig;
  /** Bot token / SMTP password / webhook signing secret is stored (never returned). */
  has_secret: boolean;
}
export interface ChannelsResponse { channels: NotifyChannel[]; key_storage: KeyStorage }
export interface ChannelInput {
  kind?: ChannelKind; name?: string; enabled?: boolean; min_severity?: Severity; events?: ChannelEvent[];
  config?: TelegramConfig | EmailConfig | WebhookChannelConfig;
  /** Write-only; empty string clears it. */
  secret?: string;
}

// SSE events on /api/v1/stream

export type ContainerEventItem = Omit<ContainerInfo, "history">;
export interface AgentEvent { run_id: string; conversation_id: string | null; status: AgentRunStatus; step: AgentStep | null }
export interface AgentDeltaEvent { run_id: string; conversation_id: string; text: string }

export interface StreamEventMap {
  metrics: HostMetrics;
  containers: ContainerEventItem[];
  alert: Alert;
  mode: ModeState;
  agent: AgentEvent;
  agent_delta: AgentDeltaEvent;
  report: ReportSummary;
  settings: { generation: number };
}
export type StreamEventName = keyof StreamEventMap;
