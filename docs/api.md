# TServerMonitor HTTP API

`GET` endpoints are read-only. Write endpoints are `POST /api/v1/agent/trigger` and the
**admin** endpoints marked below. Responses are JSON.
Timestamps are Unix epoch **milliseconds** (`i64`). Byte counts are integers in bytes,
rates are per second unless the field name says otherwise.

Authentication: when the environment variable `TSM_API_TOKEN` is set, every `/api/*`
and `/mcp` request needs `Authorization: Bearer <token>`. Because `EventSource`
cannot send headers, `GET /api/v1/stream` also accepts `?token=<token>`.
A request without a valid token gets `401 {"error": "unauthorized"}`.

Admin endpoints additionally require that a token is configured at all (otherwise `403`), and
browser requests whose `Origin` does not match `Host` are refused with `403`. Validation errors
are `400 {"error": "<中文说明>"}`.

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
}
interface AgentStep {
  seq: number; ts: number; kind: "tool_call" | "tool_result" | "message" | "error";
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
interface ResolvedModel { provider: string; source: "db" | "config"; api_format: ApiFormat; base_url: string; model: string; auth: AuthStyle; effort: Effort }
```

### SSE events (`/api/v1/stream`)

| event | data |
| --- | --- |
| `metrics` | `HostMetrics` (every sample, default 10 s) |
| `containers` | `ContainerInfo[]` without `history` (every container poll); append one point per event client-side |
| `alert` | `Alert` (new or updated) |
| `mode` | `{ mode: Mode; reason: string; since: number }` |
| `agent` | `{ run_id: string; status: AgentRun["status"]; step: AgentStep \| null }` (`step` null = status change only) |
| `report` | `ReportSummary` |
| `settings` | `{ generation: number }` (runtime settings changed; refetch) |

A `ping` comment is sent every 15 s.

## MCP

`POST/GET /mcp` serves the Model Context Protocol over Streamable HTTP. Tools:
`get_health_snapshot`, `list_alerts { status?, limit? }`, `get_latest_report { kind? }`,
`get_report { id }`, `list_findings`. All are read-only.

## Outbound webhooks

When configured (`[[notify.webhooks]]`), the daemon POSTs
`{ "event": "alert" | "report", "data": Alert | ReportSummary, "sent_at": number }`.
If a secret env var is configured, the header `X-TSM-Signature: sha256=<hex hmac of body>` is added.
