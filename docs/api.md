# TServerMonitor HTTP API

`GET` endpoints are read-only. Write endpoints are `POST /api/v1/agent/trigger`, the account endpoints, the
**admin** endpoints and the **ops** endpoint marked below. Responses are JSON.
Timestamps are Unix epoch **milliseconds** (`i64`). Byte counts are integers in bytes,
rates are per second unless the field name says otherwise.

Authentication: every `/api/*` and `/mcp*` request needs one of
- the **session cookie** `tsm_session` (HttpOnly, SameSite=Strict) set by `POST /api/v1/auth/login` or the
  setup wizard; browser writes must be same-origin (`Origin` must match `Host`, else `403 cross_origin`);
- an **API token** `Authorization: Bearer tsm_...` created under Settings (scope `read` or `ops`);
- the deprecated static tokens: `Bearer $TSM_API_TOKEN` (read + settings) and `X-TSM-Ops-Token: $TSM_OPS_TOKEN`
  (server changes), when those env vars are set.

Errors from the auth layer carry a `code`: `{"error": "...", "code": "setup_required" | "login_required" |
"sudo_required" | "scope_required" | "user_required" | "cross_origin" | "forbidden"}`. Before the first
administrator exists every protected request answers `401 setup_required`.

| Group | Who may call |
| --- | --- |
| public | `GET /api/v1/auth/state`, `POST /api/v1/auth/setup`, `POST /api/v1/auth/login`, the dashboard files |
| read (everything else) | any signed-in account or token |
| **admin** (marked below) | a signed-in account, or `TSM_API_TOKEN`; API tokens cannot change settings |
| **ops** (`POST /api/v1/ops/run`, `/mcp/ops`) | an account that confirmed its password within 10 minutes (`POST /api/v1/auth/sudo`), an `ops` API token, or `TSM_OPS_TOKEN` |
| account (`/api/v1/auth/*` below) | signed-in accounts only (not tokens) |

### Account endpoints

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v1/auth/state` | `{ setup_required, authenticated, kind: "session" \| "token" \| "legacy" \| null, user: { id, username } \| null, sudo_until }` |
| POST | `/api/v1/auth/setup` body `{ code, username, password }` | creates the first administrator and signs in (`Set-Cookie`); `400` wrong code / weak password, `409` already done |
| POST | `/api/v1/auth/login` body `{ username, password }` | `{ user }` + `Set-Cookie`; `401 bad_credentials`; 5 failures lock that address and name for 15 minutes |
| POST | `/api/v1/auth/logout` | clears the session |
| POST | `/api/v1/auth/sudo` body `{ password }` | `{ sudo_until }` (now + 10 min) |
| POST | `/api/v1/auth/password` body `{ current, new }` | signs out the account's other sessions |
| GET / DELETE | `/api/v1/auth/sessions`, `/api/v1/auth/sessions/{id}` | own sessions `{ id, created_at, last_seen, expires_at, remote, user_agent, current }[]` |
| GET / POST / DELETE | `/api/v1/auth/users` body `{ username, password }`, `/api/v1/auth/users/{id}` | administrators; create and delete need sudo; the last account and yourself cannot be deleted |
| GET / POST / DELETE | `/api/v1/auth/tokens` body `{ name, scope: "read" \| "ops", expires_days?: number \| null }`, `/api/v1/auth/tokens/{id}` | POST (sudo) returns `{ token, record }` once; DELETE revokes |

Validation errors are `400 {"error": "<中文说明>"}`.

Alert `source` is `host`, `docker`, `security`, `database` or a log source name. `DbStatus.metrics`
keys vary by engine (e.g. `threads_connected`, `qps`, `buffer_hit_pct`, `connection_usage_pct`, `active`,
`long_running`, `tps`); show unknown keys as-is.

Errors use `{"error": "<message>"}` with a 4xx/5xx status.

## Types

```ts
type Severity = "info" | "warning" | "critical";            // alerts
type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
type Mode = "normal" | "high_log" | "idle_audit" | "yield";
// normal: regular schedule; high_log: error/log burst detected, deep analysis;
// idle_audit: quiet window, history and security audit; yield: host busy, AI and deep work paused

interface DiskUsage { mount: string; fs: string; used: number; total: number }
interface NetIf { name: string; rx_bps: number; tx_bps: number }

interface HostMetrics {
  ts: number; hostname: string; os: string; kernel: string; uptime_secs: number;
  cpu_pct: number; cpu_cores: number; load1: number; load5: number; load15: number;
  mem_used: number; mem_total: number; swap_used: number; swap_total: number;
  disk_read_bps: number; disk_write_bps: number; net_rx_bps: number; net_tx_bps: number;
  disks: DiskUsage[]; nets: NetIf[];
}

interface HealthDimensions {
  cpu: number; memory: number; disk: number; logs: number;
  security: number; containers: number; database: number;   // each 0-100, higher is healthier
}

interface Snapshot {
  generated_at: number;
  host: HostMetrics | null;                 // null until the first sample
  health: { score: number; dimensions: HealthDimensions; source: "ai" | "rules" };
  mode: { mode: Mode; reason: string; since: number };
  containers: { total: number; running: number; unhealthy: number; restart_loops: number; oom: number };
  alerts_open: { critical: number; warning: number; info: number };
  ai: AiStatus;
  latest_report: ReportSummary | null;
}

interface AiStatus {
  enabled: boolean; reason: string | null;    // reason is set when disabled ("no api key", "node not found" ...)
  format: "responses" | "messages" | null; model: string | null;
  runs_today: number; daily_budget: number; running: string | null;  // running = run id
}

interface MetricPoint {
  ts: number; cpu_pct: number; mem_pct: number; swap_pct: number; disk_pct: number;
  load1: number; disk_read_bps: number; disk_write_bps: number; net_rx_bps: number; net_tx_bps: number;
}

interface ContainerInfo {
  id: string; name: string; image: string;
  state: string;            // running | exited | restarting | paused | created | dead
  status: string;           // docker human status, e.g. "Up 3 hours"
  health: string | null;    // healthy | unhealthy | starting | null
  restart_count: number; restart_loop: boolean; oom_killed: boolean;
  cpu_pct: number;          // like `docker stats`: 100 = one full core, can exceed 100
  mem_used: number; mem_limit: number;   // mem_limit 0 = no memory limit set
  net_rx: number; net_tx: number;        // cumulative bytes since container start
  started_at: number | null;
  history: { ts: number; cpu_pct: number; mem_used: number }[];   // last 60 samples
}

interface LogSource {
  name: string; kind: string;    // kind: php_error | php_slow | nginx_access | nginx_error | node | mysql_slow | generic | docker
  path: string | null; container: string | null;
  lines_total: number; errors_total: number; rate_per_min: number; errors_per_min: number;
}

interface LogCluster {
  fingerprint: string; source: string; level: string;   // error | warning | info | slow
  template: string; sample: string; count: number; first_seen: number; last_seen: number;
}

interface Finding {
  id: number; category: string;   // port | login | update | kernel | network | db | container | config
  severity: FindingSeverity; title: string; detail: string; evidence: string;
  first_seen: number; last_seen: number; resolved: boolean;
}

interface Alert {
  id: number; severity: Severity; source: string; title: string; summary: string;
  suggestion: string | null; fingerprint: string; created_at: number; last_seen: number;
  count: number; status: "open" | "resolved"; notified: boolean;
  acked_at: number | null;        // acknowledged: re-notified only on escalation
  silenced_until: number | null;  // no notifications until then (carries over to new alerts with the same fingerprint)
}

interface Diagnosis {
  health_score: number; summary: string; dimensions: HealthDimensions;
  root_causes: { title: string; evidence: string; confidence: "low" | "medium" | "high" }[];
  security_risks: { title: string; severity: FindingSeverity; detail: string; recommendation: string }[];
  recommendations: {
    title: string; category: "code" | "config" | "infra" | "database" | "security";
    priority: "high" | "medium" | "low"; detail: string; expected_impact: string;
  }[];
  anomalies: { title: string; detail: string; severity: Severity }[];
}

type ReportKind = "hourly" | "daily" | "incident" | "audit";
interface ReportSummary {
  id: number; kind: ReportKind; created_at: number; health_score: number;
  title: string; summary: string; generated_by: "ai" | "rules"; model: string | null; run_id: string | null;
}
interface Report extends ReportSummary { body: Diagnosis }

interface AgentRun {
  id: string;
  trigger: string;   // "manual" | "schedule:hourly" | "schedule:daily" | "schedule:idle-window" | "burst:<sources>" (+ " (deferred)")
  kind: ReportKind;
  status: "running" | "succeeded" | "failed" | "fallback";
  started_at: number; finished_at: number | null; model: string | null;
  steps_count: number; error: string | null; report_id: number | null;
  conversation_id: string | null;
}
// AgentRun.kind is a ReportKind or "chat"; AgentRun.status may also be "cancelled".
interface AgentStep {
  seq: number; ts: number; kind: "user" | "tool_call" | "tool_result" | "message" | "error";
  tool: string | null; input: unknown | null; output: unknown | null; text: string | null;
}
```

## Endpoints

| Method | Path | Response |
| --- | --- | --- |
| GET | `/api/v1/status` | `{ version, platform, started_at, mode, ai: AiStatus, collectors: Record<string, { ok: boolean; detail: string \| null }> }` |
| GET | `/api/v1/snapshot` | `Snapshot` |
| GET | `/api/v1/metrics?range=1h\|6h\|24h\|7d\|30d` | `{ step_secs: number; points: MetricPoint[] }` |
| GET | `/api/v1/containers` | `ContainerInfo[]` |
| GET | `/api/v1/containers/{id}/logs?tail=200` | `{ lines: { ts: number \| null; stream: "stdout" \| "stderr"; text: string }[] }` (redacted) |
| GET | `/api/v1/logs/sources` | `LogSource[]` |
| GET | `/api/v1/logs/rates?range=1h\|6h\|24h\|7d\|30d` (default 24h) | `{ step_secs: number; series: { source: string; points: { ts: number; lines: number; errors: number }[] }[] }` |
| GET | `/api/v1/logs/clusters?source=&level=&limit=100` | `LogCluster[]` sorted by `last_seen` desc |
| GET | `/api/v1/logs/daily-errors?days=365` | `{ date: "YYYY-MM-DD"; count: number }[]` |
| GET | `/api/v1/findings?include_resolved=false` | `Finding[]` |
| GET | `/api/v1/access?window=15` (1..60 minutes) | `{ sources: string[]; stats: AccessStats }` from `nginx_access` sources, kept in memory for 1 h; client addresses unmasked |
| GET | `/api/v1/ports` | `{ proto: "tcp" \| "udp"; addr: string; port: number; process: string \| null; exposed: boolean }[]` |
| GET | `/api/v1/db` | `{ name: string; kind: "mysql" \| "postgres"; ok: boolean; error: string \| null; metrics: Record<string, number>; ts: number }[]` |
| GET | `/api/v1/alerts?status=open\|all&limit=100` | `Alert[]` newest first |
| GET | `/api/v1/reports?kind=&limit=50` | `ReportSummary[]` newest first |
| GET | `/api/v1/reports/latest?kind=` | `Report` or 404 |
| GET | `/api/v1/reports/{id}` | `Report` |
| GET | `/api/v1/agent/runs?limit=50` | `AgentRun[]` newest first |
| GET | `/api/v1/agent/runs/{id}` | `AgentRun & { steps: AgentStep[] }` |
| POST | `/api/v1/agent/trigger` body `{ "kind": ReportKind }` | `202 { run_id: string }`; `409` when a run is already in progress |
| GET | `/api/v1/stream` | Server-Sent Events, see below |
| GET | `/api/v1/settings/providers` | `{ providers: Provider[]; key_storage: "env" \| "file" \| "unavailable" }` |
| POST (admin) | `/api/v1/settings/providers` body `ProviderInput` (`name`, `api_format`, `base_url` required) | `{ id }` |
| PATCH (admin) | `/api/v1/settings/providers/{id}` body `ProviderInput` | `{ id }`; changing `base_url` of a provider with a stored key requires `api_key`; config-file providers are read-only (`400`) |
| DELETE (admin) | `/api/v1/settings/providers/{id}` | `{ ok: true }`; routes using it are removed |
| POST (admin) | `/api/v1/settings/models` body `{ provider_id?, api_format?, base_url?, auth?, api_key? }` | `{ models: string[] }` from `{base_url}/models`; a stored key is only sent to the URL it was saved for |
| GET | `/api/v1/conversations?kind=chat\|task&limit=100` | `Conversation[]` newest activity first |
| GET | `/api/v1/conversations/{id}` | `Conversation` with `runs: (AgentRun & { steps: AgentStep[] })[]` (oldest first) instead of the count |
| POST (admin) | `/api/v1/conversations` body `{ title?, context?, message? }` | `201 { id, run_id: string \| null }`; with `message` the first reply starts at once |
| POST (admin) | `/api/v1/conversations/{id}/messages` body `{ text }` (≤ 8000 chars) | `202 { run_id }`; `409` while this conversation has a running turn or both interactive slots are busy |
| DELETE (admin) | `/api/v1/conversations/{id}` | `{ ok: true }`; only `kind = "chat"` (scheduled runs are kept with their reports) |
| POST (admin) | `/api/v1/agent/runs/{id}/cancel` | `{ ok: true }`; `404` when the run is not active |
| POST (admin) | `/api/v1/alerts/{id}/ack` | `Alert` |
| POST (admin) | `/api/v1/alerts/{id}/silence` body `{ minutes }` (0..10080, 0 clears) | `Alert` |
| POST (admin) | `/api/v1/alerts/{id}/close` | `Alert` (resolved and acknowledged) |
| GET | `/api/v1/settings/notify` | `{ channels: NotifyChannel[]; key_storage }` (config-file channels have ids `config:*` and are read-only) |
| POST (admin) | `/api/v1/settings/notify` body `ChannelInput` | `{ id }` |
| PATCH / DELETE (admin) | `/api/v1/settings/notify/{id}` | changing the destination (Telegram `api_base`, SMTP host/port/user, webhook URL) of a channel with a stored secret requires `secret` |
| POST (admin) | `/api/v1/settings/notify/{id}/test` | `{ ok: true }`, or `502` with the delivery error |
| GET | `/api/v1/packages` | `PackageReport & { updater: { available: boolean; socket: string } }` |
| POST (admin) | `/api/v1/packages/check` | `PackageReport` (lists again now; never refreshes the index) |
| GET | `/api/v1/packages/jobs` | `PackageJob[]` (latest 20, without `log`) |
| GET | `/api/v1/packages/jobs/{id}` | `PackageJob` with `log` |
| POST (admin) | `/api/v1/packages/jobs` body `{ op: "refresh" \| "upgrade_security" \| "upgrade_all" \| "upgrade_packages"; packages?: string[] }` | `202 { id }`; `400` when the update helper is not installed, a job is running, or a package name is invalid. Output streams as `package_job` events |
| GET | `/api/v1/access/history?range=1h\|6h\|24h\|7d\|30d` | `AccessStats` from the persisted per-minute rollups (top lists and latency only up to 24h) |
| GET | `/api/v1/ops/capabilities` | `OpsCapabilities` (helper reachable, enabled domains and allowed operations, dry-run, why writes are off) |
| GET | `/api/v1/ops/read/{call}?path=` | `{ source: "helper" \| "local"; data }` for `docker.containers`, `docker.images`, `docker.volumes`, `docker.networks`, `nginx.sites`, `nginx.files`, `nginx.file` (`path`), `firewall.status`, `ssh.config`, `ssh.keys`. Falls back to what the daemon can read itself; `503` when only the helper can answer |
| GET | `/api/v1/ssh/sessions` | `{ user, tty, since, from }[]` from `who` |
| GET | `/api/v1/ops/jobs?domain=&limit=` | `OpsJob[]` without `log` |
| GET | `/api/v1/ops/jobs/{id}` | `OpsJob` with `log` |
| GET | `/api/v1/ops/audit?limit=` | `AuditEntry[]`, newest first (includes refused requests) |
| GET | `/api/v1/ops/pending` | `PendingChange[]` firewall/sshd changes waiting for confirmation |
| POST (ops) | `/api/v1/ops/run` body `{ call; args?; dry_run? }` | `OpsJob` after up to 20 s (`status` may still be `running`; follow `ops_job` events). See the call list below. `403` not allowed / no helper / `sudo_required` / `scope_required`, `400` invalid, `409` busy or stale `base_sha256`, `502` the change failed and was rolled back |
| GET | `/api/v1/tasks` | `{ tasks: Task[]; system: SystemJob[] }` (`system` = fixed `[schedule]` jobs, read-only) |
| POST (admin) | `/api/v1/tasks` body `TaskInput` (`name`, `trigger`, `prompt_id` required) | `{ id }` |
| PATCH (admin) | `/api/v1/tasks/{id}` body `TaskInput` | `{ id }` |
| DELETE (admin) | `/api/v1/tasks/{id}` | `{ ok: true }`; built-in tasks can only be disabled (`400`) |
| POST (admin) | `/api/v1/tasks/{id}/run` | `{ run_id: string \| null; deferred: boolean }` (deferred while another analysis runs or the host is busy) |
| GET | `/api/v1/prompts` | `Prompt[]` (built-ins first) |
| POST (admin) | `/api/v1/prompts` body `{ name, description?, body }` | `{ id }` |
| PATCH / DELETE (admin) | `/api/v1/prompts/{id}` | built-ins are read-only (`400`); a prompt used by a task cannot be deleted (`400`) |
| POST (admin) | `/api/v1/prompts/generate` body `{ description }` | `{ body }` drafted by the model (route `prompt_gen`, no tools; recorded as a conversation); `502` with the reason on failure |
| GET | `/api/v1/settings/routing` | `{ kinds: { kind, label, resolved: ResolvedModel \| null }[]; efforts: Effort[]; routes: Route[] }` |
| PUT (admin) | `/api/v1/settings/routing` body `{ routes: Route[] }` | same as GET; replaces all routes |

```ts
type ApiFormat = "responses" | "messages";
type AuthStyle = "api_key" | "bearer";
type Effort = "" | "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max"; // "" = model default
interface Provider {
  id: string; name: string; source: "db" | "config"; api_format: ApiFormat; base_url: string;
  auth: AuthStyle; default_model: string; has_key: boolean; key_env?: string; updated_at: number | null;
}
interface ProviderInput { name?; api_format?; base_url?; auth?; default_model?; api_key?: string /* write-only, "" clears */ }
// kind: default | hourly | daily | incident | audit | chat | log_scan | security_check | package_advice | prompt_gen
// provider: a DB provider id or a config profile name; empty model = provider default
interface Route { kind: string; provider: string; model: string; effort: Effort }
// Every agent run belongs to a conversation. Scheduled runs get one each ("c_<run id>");
// a chat holds one run per user turn. context: one of {report_id} | {alert_id} | {run_id} | {text}.
interface Conversation {
  id: string; title: string; kind: string /* "chat" or a report kind */; context: object | null;
  created_at: number; updated_at: number; last_status: AgentRun["status"] | null; runs: number;
}
type Trigger =
  | { type: "interval"; every_mins: number }            // 5..10080
  | { type: "daily"; at: "HH:MM" }                       // local time, fires once per day (catch-up later the same day)
  | { type: "log_threshold"; source: string | null; metric: "lines" | "errors"; count: number; min_interval_mins: number }
  | { type: "burst" }                                    // with the built-in incident analysis
  | { type: "manual" };
interface Task {
  id: string; name: string; enabled: boolean; builtin: boolean; trigger: Trigger; prompt_id: string;
  route_kind: string; last_fired_at: number | null; cursor: number | null; last_run_id: string | null;
  created_at: number; updated_at: number;
}
interface Prompt { id: string; name: string; description: string; body: string; builtin: boolean; route_kind: string; updated_at: number | null }
// Task runs are reports with kind "custom"; their conversation kind is the task's route_kind.
type ChannelEvent = "alert" | "report" | "digest";
interface NotifyChannel {
  id: string; name: string; kind: "telegram" | "email" | "webhook"; source: "db" | "config"; enabled: boolean;
  min_severity: Severity; events: ChannelEvent[]; has_secret: boolean;
  config: { chat_id; api_base; bot_enabled; allowed_user_ids: number[] }          // telegram
        | { host; port; security: "starttls" | "tls" | "none"; username; from; to: string[] } // email
        | { url };                                                                 // webhook
}
// ChannelInput = Partial<NotifyChannel without id/source/has_secret> & { secret?: string /* write-only */ }
// Webhooks receive every alert; telegram/email only at or above min_severity. "report" on chat/email
// channels means the daily report and critical incidents; "digest" is the hourly warning summary.
interface AccessStats {
  window_mins: number; requests: number; requests_per_min: number;
  status: [number, number, number, number]; // 2xx, 3xx, 4xx, 5xx
  error_rate_5xx: number; bytes: number;
  series: { ts: number; requests: number; s4xx: number; s5xx: number }[];  // per minute
  top_paths: { path: string /* "METHOD /templated/<n>" */; requests: number; s5xx: number }[];
  top_ips: { ip: string; requests: number }[];
}
interface PackageReport {
  checked_at: number | null; managers: ("apt" | "dnf" | "brew")[]; errors: string[]; in_container: boolean;
  packages: { manager: "apt" | "dnf" | "brew"; name: string; current: string | null; available: string; source: string | null; security: boolean }[];
}
interface PackageJob {
  id: number; op: string; packages: string[]; status: "running" | "succeeded" | "failed" | "unknown";
  exit_code: number | null; log?: string; started_at: number; finished_at: number | null;
}
interface ResolvedModel { provider: string; source: "db" | "config"; api_format: ApiFormat; base_url: string; model: string; auth: AuthStyle; effort: Effort }
```

### Ops calls (`POST /api/v1/ops/run`)

| call | args | notes |
| --- | --- | --- |
| `docker.container` | `{ id, action: start\|stop\|restart\|kill\|remove }` | protected containers can only be started; volumes are kept |
| `docker.project` | `{ name, action: start\|stop\|restart }` | containers with `com.docker.compose.project = name` |
| `docker.image_pull` | `{ reference }` | public images; progress streams as job log |
| `docker.image_remove` | `{ id, force? }` | |
| `docker.image_prune` / `docker.volume_prune` | `{}` | |
| `docker.volume_remove` | `{ name }` | |
| `nginx.test` / `nginx.reload` | `{}` | reload runs `nginx -t` first |
| `nginx.site` | `{ name, enabled }` | symlink in `sites-enabled`, or `.conf` ↔ `.conf.disabled` |
| `nginx.write` | `{ path, content, base_sha256? }` | `base_sha256` from `nginx.file`; omit for a new file. Dry run returns `result.diff` |
| `firewall.add` | `{ action: allow\|deny\|reject\|limit, port, proto?: tcp\|udp\|any, from? }` | result `{ pending }` |
| `firewall.delete` | `{ spec }` | `spec` exactly as listed by `firewall.status`; result `{ pending }` |
| `firewall.toggle` | `{ enabled }` | ufw only; result `{ pending }` |
| `ssh.set` | `{ options: { [key]: value } }` | keys from `ssh.config.options`; dry run returns `result.diff`; result `{ pending }` |
| `ssh.key_add` | `{ user, key }` | one public key line, no options |
| `ssh.key_remove` | `{ user, fingerprint }` | |
| `pending.confirm` / `pending.revert` | `{ id }` | confirm is dashboard-only (refused over MCP) |

```ts
interface OpsJob {
  id: number; domain: string; call: string; summary: string; args: unknown; dry_run: boolean;
  via: "web" | "mcp"; remote: string | null; status: "running" | "succeeded" | "failed" | "unknown";
  error: string | null; result: Record<string, unknown> | null; log?: string; started_at: number; finished_at: number | null;
}
interface PendingChange { id: string; domain: "firewall" | "ssh"; summary: string; created_at: number; deadline: number; via: string }
interface AuditEntry { id: number; ts: number; via: string; remote: string | null; call: string; summary: string; dry_run: boolean; outcome: "started" | "succeeded" | "failed" | "refused"; detail: string | null; job_id: number | null }
```

`AccessStats` additionally carries `latency { p50_ms, p95_ms, p99_ms, samples } | null`, `slow_paths`,
`top_hosts`, `user_agents` (browser / bot / tool / scanner / empty / other), `suspicious` (scanner probes or
mostly 4xx), and `top_ips[].s4xx` / `scan`; series points carry `p95_ms`.

### SSE events (`/api/v1/stream`)

| event | data |
| --- | --- |
| `metrics` | `HostMetrics` (every sample, default 10 s) |
| `containers` | `ContainerInfo[]` without `history` (every container poll); append one point per event client-side |
| `alert` | `Alert` (new or updated) |
| `mode` | `{ mode: Mode; reason: string; since: number }` |
| `agent` | `{ run_id: string; conversation_id: string \| null; status: AgentRun["status"]; step: AgentStep \| null }` (`step` null = status change only) |
| `agent_delta` | `{ run_id; conversation_id; text }` streamed reply text of a chat turn (not persisted; the full text arrives as a `message` step) |
| `report` | `ReportSummary` |
| `settings` | `{ generation: number }` (runtime settings changed; refetch) |
| `package_job` | `{ id; status; line: string \| null }` one output line, or a status change when `line` is null |
| `ops_job` | same shape as `package_job`, for ops helper jobs |
| `ops_pending` | `PendingChange[]` (the full current list) whenever it changes |

A `ping` comment is sent every 15 s.

## MCP

`POST/GET /mcp` serves the Model Context Protocol over Streamable HTTP. Tools:
`get_health_snapshot`, `list_alerts { status?, limit? }`, `get_latest_report { kind? }`,
`get_report { id }`, `list_findings`, plus the analysis tools shared with the built-in agent:
`get_system_status`, `analyze_logs { since_hours?, source? }`, `get_access_stats { window_mins? }`
(client addresses masked), `get_host_metrics { range }`, `search_log_clusters { source?, level?, query?, since_hours?, limit? }`,
`list_containers`, `list_package_updates`, `get_access_history { range }`, and the server inventory:
`get_ops_capabilities`, `docker_inventory`, `docker_list_images`, `docker_list_volumes`, `docker_list_networks`,
`nginx_list_sites`, `nginx_list_files`, `nginx_get_file { path }` (secret values replaced with `<redacted>`),
`firewall_status`, `ssh_get_config`, `ssh_list_keys`, `ssh_list_sessions`, `list_ops_jobs`, `get_ops_job`,
`list_pending_changes`. These are read-only; the agent's workspace/script tools are not exposed, and
package upgrades are never available over MCP.

`/mcp` needs any API token (or session); `/mcp/ops` serves the same tools plus write tools and needs an `ops` token. Every write
tool defaults to `dry_run: true`; it returns `{ job_id, status, dry_run, error, result, log }` after up to
120 s. Firewall and sshd changes are provisional (`result.pending`) and revert unless a person confirms them
in the dashboard; `revert_change { id }` is available, confirming is not. `nginx_write_file` refuses content
that still contains redaction placeholders. See [mcp.md](mcp.md) for client configuration.

The MCP endpoints accept loopback `Host` headers plus `server.mcp_allowed_hosts`.

## Outbound webhooks

When configured (`[[notify.webhooks]]`), the daemon POSTs
`{ "event": "alert" | "report", "data": Alert | ReportSummary, "sent_at": number }`.
If a secret env var is configured, the header `X-TSM-Signature: sha256=<hex hmac of body>` is added.
