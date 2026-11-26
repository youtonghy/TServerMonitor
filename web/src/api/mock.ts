// Development mock (VITE_MOCK=1). Generates data that conforms to docs/api.md and simulates the SSE stream.
// Never imported by production builds.
import { ApiError, type Api } from "./client";
import { mockAuth, opsMock } from "./mock-ops";
import { withSudo } from "./client";
import type { AccountUser, ApiTokenRecord, AuthState, SessionView } from "./types";
import type {
  AgentRun, AgentRunDetail, AgentStep, AiStatus, Alert, ContainerInfo, ContainerLogLine, DailyErrorCount, DbStatus,
  Diagnosis, Finding, HostMetrics, LogCluster, LogRatesResponse, LogSource, MetricPoint, MetricsRange, ModeState,
  PortInfo, Report, ReportKind, ReportSummary, Snapshot, StreamEventMap, StreamEventName,
} from "./types";
import type { Conversation, ConversationDetail, NotifyChannel, PackageJob, PackageOp, PackagesResponse, Prompt, Provider, ResolvedModel, Route, RoutingResponse, SystemJob, Task } from "./types";

const GiB = 1024 ** 3;
const MiB = 1024 ** 2;
const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const BOOT = Date.now();

// Deterministic noise so history charts are stable across reloads.
function hash(n: number): number {
  let x = Math.imul(n ^ 0x9e3779b9, 0x85ebca6b);
  x ^= x >>> 13;
  x = Math.imul(x, 0xc2b2ae35);
  x ^= x >>> 16;
  return (x >>> 0) / 4294967296;
}
const noise = (ts: number, salt: number) => hash(Math.floor(ts / 1000) * 31 + salt) - 0.5;
const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v));
const delay = <T,>(value: T, ms = 180 + Math.random() * 320): Promise<T> =>
  new Promise(resolve => setTimeout(() => resolve(structuredClone(value)), ms));

// Host

const CORES = 8;
const MEM_TOTAL = 16 * GiB;
const SWAP_TOTAL = 4 * GiB;
const DISK_TOTALS = [
  { mount: "/", fs: "ext4", total: 100 * 1e9, base: 0.66 },
  { mount: "/data", fs: "xfs", total: 500 * 1e9, base: 0.81 },
  { mount: "/boot", fs: "ext4", total: 1 * 1e9, base: 0.34 },
];

function wave(ts: number) {
  const hourOfDay = (ts / HOUR) % 24;
  const daily = Math.sin(((hourOfDay - 8) / 24) * Math.PI * 2); // busier in the afternoon
  const fast = Math.sin(ts / (7 * MIN));
  return { daily, fast };
}

function pointAt(ts: number): MetricPoint {
  const { daily, fast } = wave(ts);
  const burst = ts > BOOT - 95 * MIN && ts < BOOT - 70 * MIN ? 28 : 0;
  const cpu = clamp(32 + daily * 14 + fast * 6 + noise(ts, 1) * 12 + burst, 2, 99);
  const mem = clamp(63 + daily * 5 + noise(ts, 2) * 3 + burst * 0.3, 10, 98);
  const swap = clamp(18 + mem * 0.08 + noise(ts, 3) * 2, 0, 100);
  const daysAgo = (BOOT - ts) / DAY;
  const disk = clamp(74 - daysAgo * 0.12 + noise(ts, 4) * 0.2, 0, 100);
  const load1 = clamp((cpu / 100) * CORES * 0.9 + noise(ts, 5) * 0.8, 0.05, 32);
  return {
    ts,
    cpu_pct: round(cpu), mem_pct: round(mem), swap_pct: round(swap), disk_pct: round(disk), load1: round(load1, 2),
    disk_read_bps: Math.round(clamp(6 * MiB + daily * 3 * MiB + noise(ts, 6) * 5 * MiB + burst * 0.4 * MiB, 0, 1e10)),
    disk_write_bps: Math.round(clamp(3 * MiB + daily * 1.5 * MiB + noise(ts, 7) * 3 * MiB + burst * 0.8 * MiB, 0, 1e10)),
    net_rx_bps: Math.round(clamp(12 * MiB + daily * 6 * MiB + noise(ts, 8) * 8 * MiB, 0, 1e10)),
    net_tx_bps: Math.round(clamp(5 * MiB + daily * 3 * MiB + noise(ts, 9) * 4 * MiB, 0, 1e10)),
  };
}

function round(v: number, digits = 1): number {
  const f = 10 ** digits;
  return Math.round(v * f) / f;
}

let live = pointAt(Date.now());

function hostAt(ts: number): HostMetrics {
  // Random walk around the deterministic curve for a lively realtime feed.
  const target = pointAt(ts);
  const spike = Math.random() < 0.03 ? 30 + Math.random() * 25 : 0;
  const cpu = clamp(live.cpu_pct + (target.cpu_pct - live.cpu_pct) * 0.3 + (Math.random() - 0.5) * 8 + spike, 1, 99.5);
  const mem = clamp(live.mem_pct + (target.mem_pct - live.mem_pct) * 0.2 + (Math.random() - 0.5) * 1.2, 5, 99);
  live = { ...target, cpu_pct: round(cpu), mem_pct: round(mem) };
  const load1 = round(clamp((cpu / 100) * CORES + (Math.random() - 0.5), 0.05, 32), 2);
  return {
    ts,
    hostname: "web-prod-01",
    os: "Ubuntu 24.04.1 LTS",
    kernel: "6.8.0-48-generic",
    uptime_secs: Math.floor((ts - (BOOT - 23 * DAY - 5 * HOUR)) / 1000),
    cpu_pct: live.cpu_pct, cpu_cores: CORES,
    load1, load5: round(load1 * 0.92 + 0.3, 2), load15: round(load1 * 0.85 + 0.4, 2),
    mem_used: Math.round((mem / 100) * MEM_TOTAL), mem_total: MEM_TOTAL,
    swap_used: Math.round((target.swap_pct / 100) * SWAP_TOTAL), swap_total: SWAP_TOTAL,
    disk_read_bps: target.disk_read_bps, disk_write_bps: target.disk_write_bps,
    net_rx_bps: Math.round(target.net_rx_bps * (0.8 + Math.random() * 0.4)),
    net_tx_bps: Math.round(target.net_tx_bps * (0.8 + Math.random() * 0.4)),
    disks: DISK_TOTALS.map((d, i) => ({ mount: d.mount, fs: d.fs, total: d.total, used: Math.round(d.total * (d.base + noise(ts, 20 + i) * 0.002)) })),
    nets: [
      { name: "eth0", rx_bps: target.net_rx_bps, tx_bps: target.net_tx_bps },
      { name: "docker0", rx_bps: Math.round(target.net_rx_bps * 0.18), tx_bps: Math.round(target.net_tx_bps * 0.22) },
    ],
  };
}

const RANGE_SECS: Record<MetricsRange, number> = { "1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400 };

function metricsFor(range: MetricsRange) {
  const span = RANGE_SECS[range];
  const step = Math.max(10, Math.round(span / 360 / 10) * 10);
  const end = Math.floor(Date.now() / (step * 1000)) * step * 1000;
  const points: MetricPoint[] = [];
  for (let ts = end - span * 1000 + step * 1000; ts <= end; ts += step * 1000) points.push(pointAt(ts));
  return { step_secs: step, points };
}

// Containers

interface ContainerSeed {
  id: string; name: string; image: string; state: string; status: string; health: string | null;
  restart_count: number; restart_loop: boolean; oom_killed: boolean; cpu: number; mem: number; limit: number; started: number | null;
}

const containerSeeds: ContainerSeed[] = [
  { id: "a1f3c9e2b7d4", name: "nginx", image: "nginx:1.27-alpine", state: "running", status: "Up 9 days", health: "healthy", restart_count: 0, restart_loop: false, oom_killed: false, cpu: 3.2, mem: 48 * MiB, limit: 512 * MiB, started: 9 * DAY },
  { id: "b2e4d0f1a8c3", name: "php-fpm", image: "php:8.3-fpm", state: "running", status: "Up 9 days", health: "healthy", restart_count: 0, restart_loop: false, oom_killed: false, cpu: 38.5, mem: 1.8 * GiB, limit: 4 * GiB, started: 9 * DAY },
  { id: "c3d5e1a2b9f4", name: "mysql", image: "mysql:8.4", state: "running", status: "Up 23 days (healthy)", health: "healthy", restart_count: 0, restart_loop: false, oom_killed: false, cpu: 21.7, mem: 5.2 * GiB, limit: 8 * GiB, started: 23 * DAY },
  { id: "d4c6f2b3a0e5", name: "redis", image: "redis:7.4", state: "running", status: "Up 23 days", health: null, restart_count: 0, restart_loop: false, oom_killed: false, cpu: 1.4, mem: 310 * MiB, limit: 1 * GiB, started: 23 * DAY },
  { id: "e5b7a3c4d1f6", name: "node-api", image: "registry.local/node-api:2.14.0", state: "running", status: "Up 2 hours (unhealthy)", health: "unhealthy", restart_count: 2, restart_loop: false, oom_killed: false, cpu: 12.9, mem: 720 * MiB, limit: 1 * GiB, started: 2 * HOUR },
  { id: "f6a8b4d5e2c7", name: "queue-worker", image: "registry.local/worker:2.14.0", state: "restarting", status: "Restarting (1) 12 seconds ago", health: null, restart_count: 47, restart_loop: true, oom_killed: false, cpu: 0, mem: 0, limit: 1 * GiB, started: null },
  { id: "a7c9d5e6f3b8", name: "report-builder", image: "registry.local/reports:1.3.2", state: "exited", status: "Exited (137) 41 minutes ago", health: null, restart_count: 3, restart_loop: false, oom_killed: true, cpu: 0, mem: 0, limit: 768 * MiB, started: null },
  { id: "b8d0e6f7a4c9", name: "certbot", image: "certbot/certbot:v2.11", state: "exited", status: "Exited (0) 6 hours ago", health: null, restart_count: 0, restart_loop: false, oom_killed: false, cpu: 0, mem: 0, limit: 0, started: null },
];

function containersNow(): ContainerInfo[] {
  const now = Date.now();
  return containerSeeds.map((seed, index) => {
    const running = seed.state === "running";
    const history = Array.from({ length: 60 }, (_, i) => {
      const ts = now - (59 - i) * 10_000;
      const jitter = noise(ts, 100 + index);
      return {
        ts,
        cpu_pct: running ? round(clamp(seed.cpu * (1 + jitter * 0.6) + Math.sin(i / 6 + index) * seed.cpu * 0.2, 0, 100 * CORES)) : seed.restart_loop && i % 7 < 2 ? round(8 + jitter * 6) : 0,
        mem_used: running ? Math.round(seed.mem * (1 + jitter * 0.08)) : seed.oom_killed && i < 52 ? Math.round(seed.limit * (0.6 + i / 130)) : 0,
      };
    });
    const last = history[history.length - 1];
    return {
      id: seed.id, name: seed.name, image: seed.image, state: seed.state, status: seed.status, health: seed.health,
      restart_count: seed.restart_count, restart_loop: seed.restart_loop, oom_killed: seed.oom_killed,
      cpu_pct: last.cpu_pct, mem_used: last.mem_used, mem_limit: seed.limit,
      net_rx: running ? Math.round(seed.mem * 12 + index * 9e7) : 0, net_tx: running ? Math.round(seed.mem * 7 + index * 4e7) : 0,
      started_at: seed.started === null ? null : now - seed.started,
      history,
    };
  });
}

function containerLogs(id: string, tail: number): ContainerLogLine[] {
  const seed = containerSeeds.find(c => c.id === id || c.name === id);
  if (!seed) throw new ApiError(404, "container not found");
  const now = Date.now();
  const templates: Record<string, [ContainerLogLine["stream"], string][]> = {
    "queue-worker": [
      ["stdout", "[worker] booting queue consumer, concurrency=4"],
      ["stdout", "[worker] connecting to redis://redis:6379/2"],
      ["stderr", "Error: connect ECONNREFUSED amqp://mq:5672 user=svc_worker password=[REDACTED]"],
      ["stderr", "    at TCPConnectWrap.afterConnect [as oncomplete] (node:net:1607:16)"],
      ["stderr", "[worker] fatal: broker unavailable, exiting with code 1"],
    ],
    "report-builder": [
      ["stdout", "[reports] loading 1,284,112 rows for monthly export"],
      ["stdout", "[reports] heap used 612 MB / 768 MB"],
      ["stderr", "<--- Last few GCs ---> Mark-Compact 742.1 (768.0) -> 741.8 (768.0) MB"],
      ["stderr", "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory"],
    ],
    "node-api": [
      ["stdout", "GET /api/orders 200 84ms"],
      ["stdout", "GET /healthz 503 5002ms"],
      ["stderr", "WARN upstream timeout talking to php-fpm after 5000ms (Authorization: Bearer [REDACTED])"],
      ["stdout", "POST /api/cart 201 132ms"],
    ],
  };
  const lines = templates[seed.name] ?? [
    ["stdout", `${seed.name}: request handled in ${Math.round(5 + Math.random() * 40)}ms`],
    ["stdout", `${seed.name}: ready to accept connections`],
    ["stderr", `${seed.name}: slow operation detected, client=10.0.3.[REDACTED]`],
  ];
  const count = Math.min(tail, 60);
  return Array.from({ length: count }, (_, i) => {
    const [stream, text] = lines[i % lines.length];
    return { ts: seed.name === "certbot" && i % 5 === 0 ? null : now - (count - i) * 4_000, stream, text };
  });
}

// Logs

const logSources: LogSource[] = [
  { name: "nginx-access", kind: "nginx_access", path: "/var/log/nginx/access.log", container: null, lines_total: 18_402_331, errors_total: 41_207, rate_per_min: 1840, errors_per_min: 3.1 },
  { name: "nginx-error", kind: "nginx_error", path: "/var/log/nginx/error.log", container: null, lines_total: 92_114, errors_total: 61_880, rate_per_min: 22, errors_per_min: 14.5 },
  { name: "php-error", kind: "php_error", path: "/var/log/php8.3-fpm/error.log", container: null, lines_total: 412_903, errors_total: 288_410, rate_per_min: 386, errors_per_min: 312 },
  { name: "php-slow", kind: "php_slow", path: "/var/log/php8.3-fpm/slow.log", container: null, lines_total: 20_541, errors_total: 0, rate_per_min: 6.4, errors_per_min: 0 },
  { name: "mysql-slow", kind: "mysql_slow", path: "/var/lib/mysql/slow.log", container: null, lines_total: 31_877, errors_total: 0, rate_per_min: 4.2, errors_per_min: 0 },
  { name: "node-api", kind: "node", path: null, container: "node-api", lines_total: 1_204_118, errors_total: 9_312, rate_per_min: 410, errors_per_min: 7.8 },
  { name: "queue-worker", kind: "docker", path: null, container: "queue-worker", lines_total: 8_812, errors_total: 3_901, rate_per_min: 24, errors_per_min: 11.6 },
];

function logRates(): LogRatesResponse {
  const step = 600;
  const end = Math.floor(Date.now() / (step * 1000)) * step * 1000;
  const base: Record<string, [number, number]> = {
    "nginx-access": [16000, 20], "nginx-error": [150, 90], "php-error": [600, 380], "php-slow": [60, 0],
    "mysql-slow": [40, 0], "node-api": [3800, 60], "queue-worker": [80, 30],
  };
  return {
    step_secs: step,
    series: logSources.map((source, index) => ({
      source: source.name,
      points: Array.from({ length: 144 }, (_, i) => {
        const ts = end - (143 - i) * step * 1000;
        const { daily } = wave(ts);
        const [lines, errors] = base[source.name];
        const burst = source.name === "php-error" && i > 126 ? 8 + (i - 126) * 0.6 : source.name === "queue-worker" && i > 132 ? 4 : 1;
        const n = 1 + noise(ts, 200 + index) * 0.5;
        return {
          ts,
          lines: Math.round(lines * (1 + daily * 0.45) * n * (burst > 1 ? burst * 0.7 : 1)),
          errors: Math.round(errors * n * burst * (1 + daily * 0.2)),
        };
      }),
    })),
  };
}

const clusterSeeds: Omit<LogCluster, "first_seen" | "last_seen">[] = [
  { fingerprint: "c01a", source: "php-error", level: "error", template: "PHP Fatal error: Uncaught PDOException: SQLSTATE[HY000] [2002] Connection refused in <path>:<n>", sample: "PHP Fatal error: Uncaught PDOException: SQLSTATE[HY000] [2002] Connection refused in /var/www/app/src/Db.php:88", count: 18_204 },
  { fingerprint: "c02b", source: "php-error", level: "warning", template: "PHP Warning: Undefined array key \"<key>\" in <path> on line <n>", sample: "PHP Warning: Undefined array key \"coupon\" in /var/www/app/src/Cart.php on line 213", count: 9_877 },
  { fingerprint: "c03c", source: "php-error", level: "error", template: "PHP Fatal error: Allowed memory size of <n> bytes exhausted (tried to allocate <n> bytes)", sample: "PHP Fatal error: Allowed memory size of 268435456 bytes exhausted (tried to allocate 20480 bytes)", count: 412 },
  { fingerprint: "c04d", source: "nginx-error", level: "error", template: "upstream timed out (110: Connection timed out) while reading response header from upstream, client: <ip>", sample: "upstream timed out (110: Connection timed out) while reading response header from upstream, client: 203.0.113.[REDACTED]", count: 3_291 },
  { fingerprint: "c05e", source: "nginx-error", level: "warning", template: "an upstream response is buffered to a temporary file <path>", sample: "an upstream response is buffered to a temporary file /var/cache/nginx/fastcgi_temp/3/02/0000001023", count: 1_802 },
  { fingerprint: "c06f", source: "nginx-access", level: "error", template: "<ip> \"GET /wp-login.php HTTP/1.1\" 404", sample: "198.51.100.[REDACTED] \"GET /wp-login.php HTTP/1.1\" 404", count: 22_010 },
  { fingerprint: "c070", source: "nginx-access", level: "info", template: "<ip> \"POST /api/checkout HTTP/2.0\" 502", sample: "203.0.113.[REDACTED] \"POST /api/checkout HTTP/2.0\" 502", count: 611 },
  { fingerprint: "c081", source: "mysql-slow", level: "slow", template: "SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC (Query_time: <n>s)", sample: "SELECT * FROM orders WHERE user_id = 18842 ORDER BY created_at DESC (Query_time: 4.81s)", count: 2_944 },
  { fingerprint: "c092", source: "mysql-slow", level: "slow", template: "UPDATE inventory SET stock = stock - ? WHERE sku IN (<list>) (Query_time: <n>s)", sample: "UPDATE inventory SET stock = stock - 1 WHERE sku IN ('A-1102','A-1103') (Query_time: 2.07s)", count: 803 },
  { fingerprint: "c0a3", source: "php-slow", level: "slow", template: "script_filename = <path> [<addr>] curl_exec() <path>:<n>", sample: "script_filename = /var/www/app/public/index.php [0x7f3a] curl_exec() /var/www/app/src/Payment.php:142", count: 1_240 },
  { fingerprint: "c0b4", source: "node-api", level: "error", template: "Error: upstream timeout talking to php-fpm after <n>ms", sample: "Error: upstream timeout talking to php-fpm after 5000ms", count: 4_118 },
  { fingerprint: "c0c5", source: "node-api", level: "info", template: "GET /healthz <n> <n>ms", sample: "GET /healthz 503 5002ms", count: 712 },
  { fingerprint: "c0d6", source: "queue-worker", level: "error", template: "Error: connect ECONNREFUSED <url>", sample: "Error: connect ECONNREFUSED amqp://mq:5672", count: 3_877 },
  { fingerprint: "c0e7", source: "queue-worker", level: "warning", template: "[worker] fatal: broker unavailable, exiting with code <n>", sample: "[worker] fatal: broker unavailable, exiting with code 1", count: 1_904 },
];

function logClusters(filter: { source?: string; level?: string; limit?: number }): LogCluster[] {
  const now = Date.now();
  return clusterSeeds
    .map((seed, i) => ({ ...seed, first_seen: now - (3 + i * 2) * DAY - i * HOUR, last_seen: now - Math.round(hash(i + 7) * (i < 4 ? 8 : 180)) * MIN - i * 1000 }))
    .filter(c => !filter.source || c.source === filter.source)
    .filter(c => !filter.level || c.level === filter.level)
    .sort((a, b) => b.last_seen - a.last_seen)
    .slice(0, filter.limit ?? 100);
}

function dailyErrors(days: number): DailyErrorCount[] {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Array.from({ length: days }, (_, i) => {
    const date = new Date(today.getTime() - (days - 1 - i) * DAY);
    const weekday = date.getDay();
    const base = weekday === 0 || weekday === 6 ? 40 : 140;
    const r = hash(i * 13 + 5);
    const incident = r > 0.97 ? 1800 + r * 900 : r > 0.9 ? 600 : 0;
    const recent = i > days - 3 ? 2400 : 0;
    const quiet = r < 0.06 ? 0 : 1;
    const y = date.getFullYear(), m = String(date.getMonth() + 1).padStart(2, "0"), d = String(date.getDate()).padStart(2, "0");
    return { date: `${y}-${m}-${d}`, count: Math.round((base * (0.5 + r) + incident + recent) * quiet) };
  });
}

// Security

const findings: Finding[] = (() => {
  const now = Date.now();
  return [
    { id: 41, category: "port", severity: "critical", title: "MySQL 3306 端口对公网开放", detail: "mysqld 监听 0.0.0.0:3306，防火墙未限制来源地址。", evidence: "ss -ltnp: LISTEN 0 151 0.0.0.0:3306 users:((\"mysqld\",pid=1182))", first_seen: now - 6 * DAY, last_seen: now - 2 * MIN, resolved: false },
    { id: 38, category: "login", severity: "high", title: "SSH 暴力破解尝试", detail: "过去 24 小时有 3,412 次失败的 SSH 登录，来自 214 个不同地址。", evidence: "journalctl -u ssh: Failed password for invalid user admin from 45.148.10.[REDACTED] port 52144", first_seen: now - 3 * DAY, last_seen: now - 4 * MIN, resolved: false },
    { id: 36, category: "config", severity: "high", title: "SSH 允许密码登录", detail: "sshd_config 中 PasswordAuthentication 为 yes，建议仅使用密钥登录。", evidence: "/etc/ssh/sshd_config:58 PasswordAuthentication yes", first_seen: now - 21 * DAY, last_seen: now - 10 * MIN, resolved: false },
    { id: 33, category: "update", severity: "medium", title: "12 个安全更新待安装", detail: "包括 openssl、libc6 与 nginx，其中 2 个修复了高危漏洞。", evidence: "apt list --upgradable: openssl/noble-security 3.0.13-0ubuntu3.4", first_seen: now - 5 * DAY, last_seen: now - HOUR, resolved: false },
    { id: 31, category: "container", severity: "medium", title: "容器以 root 身份运行", detail: "queue-worker 与 report-builder 未设置非特权用户。", evidence: "docker inspect queue-worker: \"User\": \"\"", first_seen: now - 9 * DAY, last_seen: now - 30 * MIN, resolved: false },
    { id: 27, category: "kernel", severity: "low", title: "内核更新后需要重启", detail: "已安装 6.8.0-49，当前仍运行 6.8.0-48。", evidence: "/var/run/reboot-required", first_seen: now - 2 * DAY, last_seen: now - HOUR, resolved: false },
    { id: 22, category: "network", severity: "low", title: "IPv6 未配置防火墙规则", detail: "ip6tables INPUT 链默认策略为 ACCEPT。", evidence: "ip6tables -S: -P INPUT ACCEPT", first_seen: now - 14 * DAY, last_seen: now - 2 * HOUR, resolved: false },
    { id: 19, category: "db", severity: "info", title: "MySQL 慢查询日志已开启", detail: "long_query_time = 1，日志增长约 40 MB/天。", evidence: "SHOW VARIABLES LIKE 'long_query_time': 1.000000", first_seen: now - 20 * DAY, last_seen: now - 3 * HOUR, resolved: false },
    { id: 12, category: "config", severity: "medium", title: "Nginx 暴露版本号", detail: "server_tokens 已关闭。", evidence: "nginx -T: server_tokens off;", first_seen: now - 30 * DAY, last_seen: now - 8 * DAY, resolved: true },
  ];
})();

const ports: PortInfo[] = [
  { proto: "tcp", addr: "0.0.0.0", port: 22, process: "sshd", exposed: true },
  { proto: "tcp", addr: "0.0.0.0", port: 80, process: "nginx", exposed: true },
  { proto: "tcp", addr: "0.0.0.0", port: 443, process: "nginx", exposed: true },
  { proto: "tcp", addr: "0.0.0.0", port: 3306, process: "mysqld", exposed: true },
  { proto: "tcp", addr: "127.0.0.1", port: 6379, process: "redis-server", exposed: false },
  { proto: "tcp", addr: "127.0.0.1", port: 9000, process: "php-fpm", exposed: false },
  { proto: "tcp", addr: "127.0.0.1", port: 8787, process: "tserver-monitor", exposed: false },
  { proto: "tcp", addr: "172.18.0.5", port: 3000, process: "node", exposed: false },
  { proto: "tcp", addr: "::", port: 22, process: "sshd", exposed: true },
  { proto: "udp", addr: "127.0.0.53", port: 53, process: "systemd-resolved", exposed: false },
  { proto: "udp", addr: "0.0.0.0", port: 123, process: null, exposed: true },
];

function dbStatus(): DbStatus[] {
  const now = Date.now();
  return [
    {
      name: "main", kind: "mysql", ok: true, error: null, ts: now - 20_000,
      metrics: { connections: 87, max_connections: 151, threads_running: 9, qps: 412.6, slow_queries: 31_877, uptime_secs: 23 * 86400, innodb_buffer_pool_hit_pct: 97.4, replication_lag_secs: 0 },
    },
    {
      name: "analytics", kind: "postgres", ok: false, error: "connection refused (127.0.0.1:5432)", ts: now - 20_000,
      metrics: {},
    },
  ];
}

// Alerts

const alerts: Alert[] = (() => {
  const now = Date.now();
  const make = (id: number, severity: Alert["severity"], source: string, title: string, summary: string, suggestion: string | null, ago: number, count: number, status: Alert["status"] = "open"): Alert =>
    ({ id, severity, source, title, summary, suggestion, fingerprint: `fp-${id}`, created_at: now - ago, last_seen: now - Math.min(ago, 3 * MIN), count, status, notified: severity !== "info", acked_at: id === 116 ? now - HOUR : null, silenced_until: null });
  return [
    make(119, "critical", "logs", "php-error 错误率激增", "5 分钟内 PHP 错误从 40/分钟 升至 312/分钟，主要为 PDO 连接被拒绝。", "检查 MySQL 连接数上限与 php-fpm 连接池配置。", 18 * MIN, 64),
    make(118, "critical", "containers", "queue-worker 重启循环", "容器在 30 分钟内重启 47 次，退出码 1。", "检查消息队列 mq:5672 是否可达。", 32 * MIN, 47),
    make(117, "warning", "containers", "report-builder 内存溢出被终止", "容器因 OOM 退出 (137)，内存上限 768 MB。", "提高内存上限或分批导出。", 41 * MIN, 1),
    make(116, "warning", "containers", "node-api 健康检查失败", "/healthz 连续 6 次返回 503。", null, 2 * HOUR, 6),
    make(114, "warning", "security", "SSH 暴力破解尝试", "24 小时内 3,412 次失败登录。", "启用 fail2ban 并关闭密码登录。", 3 * DAY, 3412),
    make(112, "info", "host", "磁盘 /data 使用率超过 80%", "当前 81%，预计 41 天后写满。", "清理旧日志或扩容。", 5 * DAY, 1),
    make(108, "warning", "host", "CPU 持续高负载", "15 分钟平均负载 7.8 超过核心数的 90%。", null, 2 * DAY, 3, "resolved"),
    make(104, "info", "db", "MySQL 慢查询增多", "慢查询较昨日上升 35%。", "为 orders.user_id 添加索引。", 6 * DAY, 12, "resolved"),
  ];
})();

// Reports and agent

const dims = (cpu: number, memory: number, disk: number, logs: number, security: number, containers: number, database: number) =>
  ({ cpu, memory, disk, logs, security, containers, database });

const diagnoses: Record<number, Diagnosis> = {
  57: {
    health_score: 64,
    summary: "PHP 应用在过去 20 分钟出现大量数据库连接被拒绝错误，直接原因是 MySQL 连接数接近上限且 queue-worker 重启循环占用连接。建议立即调高连接池上限并修复消息队列连接。",
    dimensions: dims(70, 66, 72, 31, 52, 48, 58),
    root_causes: [
      { title: "MySQL 连接数接近上限", evidence: "connections=148/151，PDOException 2002 在 18:05 后出现 18,204 次", confidence: "high" },
      { title: "queue-worker 重启循环反复建连", evidence: "47 次重启，每次启动建立 20 个数据库连接后未释放", confidence: "medium" },
      { title: "慢查询拖长连接占用时间", evidence: "orders 表按 user_id 查询平均 4.8 秒", confidence: "low" },
    ],
    security_risks: [
      { title: "数据库端口暴露在公网", severity: "critical", detail: "3306 监听所有地址，可被扫描与暴力破解。", recommendation: "将 bind-address 改为 127.0.0.1，或在防火墙中仅允许内网访问。" },
      { title: "SSH 暴力破解", severity: "high", detail: "大量失败登录来自不同地址。", recommendation: "关闭密码登录，启用 fail2ban。" },
    ],
    recommendations: [
      { title: "调高 MySQL max_connections 并限制 php-fpm 连接池", category: "database", priority: "high", detail: "将 max_connections 调至 300，pm.max_children 降至 40。", expected_impact: "消除连接被拒绝错误，错误率预计下降 95%" },
      { title: "修复 queue-worker 的消息队列地址", category: "config", priority: "high", detail: "环境变量 AMQP_URL 指向已下线的 mq 主机。", expected_impact: "停止重启循环，释放约 20 个数据库连接" },
      { title: "为 orders.user_id 添加索引", category: "database", priority: "medium", detail: "ALTER TABLE orders ADD INDEX idx_user_created (user_id, created_at)。", expected_impact: "慢查询减少约 70%" },
      { title: "限制 3306 端口仅内网访问", category: "security", priority: "high", detail: "ufw deny 3306，并修改 bind-address。", expected_impact: "关闭公网攻击面" },
      { title: "为 report-builder 分批导出", category: "code", priority: "low", detail: "按 10 万行分页读取，避免一次加载全部数据。", expected_impact: "避免 OOM" },
    ],
    anomalies: [
      { title: "PHP 错误率 8 倍突增", detail: "18:05 起 php-error 每分钟错误数从 40 升至 312。", severity: "critical" },
      { title: "CPU 短时尖峰", detail: "18:10 CPU 达到 91%，持续约 4 分钟。", severity: "warning" },
      { title: "网络出流量下降", detail: "与错误率上升同步，出流量下降 30%，疑似请求失败。", severity: "info" },
    ],
  },
  56: {
    health_score: 81,
    summary: "过去一小时主机整体平稳，CPU 与内存处于常规区间。node-api 健康检查间歇失败，需关注。",
    dimensions: dims(84, 78, 74, 76, 60, 70, 88),
    root_causes: [{ title: "node-api 上游超时", evidence: "/healthz 503，php-fpm 响应超过 5 秒", confidence: "medium" }],
    security_risks: [],
    recommendations: [
      { title: "为 node-api 健康检查设置独立超时", category: "config", priority: "medium", detail: "健康检查不应依赖 php-fpm。", expected_impact: "减少误报重启" },
    ],
    anomalies: [{ title: "node-api 健康检查失败", detail: "连续 6 次 503。", severity: "warning" }],
  },
  55: {
    health_score: 77,
    summary: "昨日主机运行稳定，平均 CPU 31%，内存 64%。/data 磁盘增长较快，预计 41 天写满；安全方面存在公网暴露的数据库端口与 SSH 暴力破解。",
    dimensions: dims(82, 75, 61, 72, 49, 80, 85),
    root_causes: [
      { title: "日志未轮转导致 /data 增长", evidence: "/data/logs 日增 2.4 GB，logrotate 未覆盖该目录", confidence: "high" },
    ],
    security_risks: [
      { title: "数据库端口暴露在公网", severity: "critical", detail: "3306 对 0.0.0.0 开放。", recommendation: "仅允许内网访问。" },
      { title: "12 个安全更新待安装", severity: "medium", detail: "包括 openssl 与 libc6。", recommendation: "在维护窗口执行 apt upgrade 并重启。" },
      { title: "IPv6 未设置防火墙", severity: "low", detail: "INPUT 默认 ACCEPT。", recommendation: "补充 ip6tables 规则。" },
    ],
    recommendations: [
      { title: "为 /data/logs 配置 logrotate", category: "infra", priority: "high", detail: "按天轮转并保留 14 天，启用压缩。", expected_impact: "磁盘增长放缓约 80%" },
      { title: "安装安全更新", category: "security", priority: "medium", detail: "apt upgrade 后重启以加载新内核。", expected_impact: "修复 2 个高危漏洞" },
      { title: "开启 OPcache 预加载", category: "config", priority: "low", detail: "opcache.preload 指向框架引导文件。", expected_impact: "PHP 响应时间下降约 10%" },
    ],
    anomalies: [{ title: "夜间磁盘写入升高", detail: "02:00 备份任务期间写入达到 180 MB/s。", severity: "info" }],
  },
  54: {
    health_score: 70,
    summary: "空闲窗口审计发现 1 个严重与 2 个高危安全问题，均与网络暴露和认证方式有关。",
    dimensions: dims(90, 80, 70, 74, 41, 78, 84),
    root_causes: [{ title: "默认安装配置未加固", evidence: "sshd 与 mysqld 均使用发行版默认配置", confidence: "medium" }],
    security_risks: [
      { title: "数据库端口暴露在公网", severity: "critical", detail: "3306 对公网开放。", recommendation: "仅允许内网访问。" },
      { title: "SSH 允许密码登录", severity: "high", detail: "PasswordAuthentication yes。", recommendation: "改为仅密钥登录。" },
      { title: "容器以 root 运行", severity: "medium", detail: "两个容器未设置 USER。", recommendation: "在 Dockerfile 中添加非特权用户。" },
      { title: "MySQL 慢查询日志开启", severity: "info", detail: "仅供参考。", recommendation: "保持开启并定期清理。" },
    ],
    recommendations: [
      { title: "关闭 SSH 密码登录", category: "security", priority: "high", detail: "PasswordAuthentication no，并重启 sshd。", expected_impact: "杜绝密码暴力破解" },
      { title: "容器使用非 root 用户", category: "infra", priority: "medium", detail: "在镜像中创建 app 用户。", expected_impact: "降低容器逃逸风险" },
    ],
    anomalies: [],
  },
};

const reportSummaries: ReportSummary[] = (() => {
  const now = Date.now();
  return [
    { id: 57, kind: "incident", created_at: now - 12 * MIN, health_score: 64, title: "PHP 错误激增事件分析", summary: diagnoses[57].summary, generated_by: "ai", model: "gpt-4.1-mini", run_id: "run_0c41" },
    { id: 56, kind: "hourly", created_at: now - 55 * MIN, health_score: 81, title: "小时巡检", summary: diagnoses[56].summary, generated_by: "rules", model: null, run_id: "run_0c3f" },
    { id: 55, kind: "daily", created_at: now - 15 * HOUR, health_score: 77, title: "每日健康报告", summary: diagnoses[55].summary, generated_by: "ai", model: "gpt-4.1-mini", run_id: "run_0c2a" },
    { id: 54, kind: "audit", created_at: now - 2 * DAY, health_score: 70, title: "空闲窗口安全审计", summary: diagnoses[54].summary, generated_by: "ai", model: "gpt-4.1-mini", run_id: "run_0b97" },
  ];
})();

function stepsFor(runId: string, start: number, kind: ReportKind, failed = false): AgentStep[] {
  const s: AgentStep[] = [];
  const push = (kindOf: AgentStep["kind"], partial: Partial<AgentStep>) =>
    s.push({ seq: s.length + 1, ts: start + s.length * 3_200, kind: kindOf, tool: null, input: null, output: null, text: null, ...partial });
  push("message", { text: `开始${kind === "incident" ? "事件" : "例行"}诊断，先读取主机快照。` });
  push("tool_call", { tool: "get_health_snapshot", input: {} });
  push("tool_result", { tool: "get_health_snapshot", output: { cpu_pct: 41.2, mem_pct: 66.1, load1: 3.4, mode: "high_log", alerts_open: { critical: 2, warning: 3, info: 1 } } });
  push("tool_call", { tool: "query_log_clusters", input: { source: "php-error", level: "error", limit: 5 } });
  push("tool_result", { tool: "query_log_clusters", output: [{ fingerprint: "c01a", count: 18204, template: "PHP Fatal error: Uncaught PDOException: SQLSTATE[HY000] [2002] Connection refused" }, { fingerprint: "c03c", count: 412, template: "Allowed memory size exhausted" }] });
  push("tool_call", { tool: "get_db_status", input: { name: "main" } });
  if (failed) {
    push("error", { text: `模型请求超时（120 秒），运行 ${runId} 中止。` });
    return s;
  }
  push("tool_result", { tool: "get_db_status", output: { ok: true, metrics: { connections: 148, max_connections: 151, threads_running: 22 } } });
  push("message", { text: "连接数已接近上限，结合 queue-worker 重启循环判断为连接泄漏。生成诊断报告。" });
  return s;
}

interface RunRecord { run: AgentRun; steps: AgentStep[] }

const runs: RunRecord[] = (() => {
  const now = Date.now();
  const make = (id: string, trigger: string, kind: ReportKind, status: AgentRun["status"], startedAgo: number, durationMs: number, report: number | null, model: string | null, error: string | null): RunRecord => {
    const started = now - startedAgo;
    const steps = status === "fallback" ? [] : stepsFor(id, started, kind, status === "failed");
    return { run: { id, trigger, kind, status, started_at: started, finished_at: started + durationMs, model, steps_count: steps.length, error, report_id: report, conversation_id: `c_${id}` }, steps };
  };
  return [
    make("run_0c41", "alert", "incident", "succeeded", 13 * MIN, 52_000, 57, "gpt-4.1-mini", null),
    make("run_0c3f", "schedule", "hourly", "fallback", 56 * MIN, 8_000, 56, null, "已达到每日 AI 预算的 80%，本次使用规则引擎"),
    make("run_0c35", "manual", "hourly", "failed", 3 * HOUR, 120_000, null, "gpt-4.1-mini", "模型请求超时（120 秒）"),
    make("run_0c2a", "schedule", "daily", "succeeded", 15 * HOUR, 74_000, 55, "gpt-4.1-mini", null),
    make("run_0b97", "mode", "audit", "succeeded", 2 * DAY, 96_000, 54, "gpt-4.1-mini", null),
  ];
})();

const ai: AiStatus = { enabled: true, reason: null, format: "responses", model: "gpt-4.1-mini", runs_today: 7, daily_budget: 24, running: null };
let mode: ModeState = { mode: "high_log", reason: "php-error 每分钟错误数 5 分钟内上升 8 倍", since: Date.now() - 18 * MIN };

// Stream simulation

type Emit = <K extends StreamEventName>(event: K, data: StreamEventMap[K]) => void;
const emitters = new Set<Emit>();
const emit: Emit = (event, data) => emitters.forEach(fn => fn(event, structuredClone(data)));

/** Starts the mock stream for one subscriber. Returns a function that stops it. */
export function startMockStream(onEvent: Emit): () => void {
  emitters.add(onEvent);
  onEvent("mode", { ...mode });
  let tick = 0;
  const timer = setInterval(() => {
    tick += 1;
    onEvent("metrics", hostAt(Date.now()));
    if (tick % 5 === 0) onEvent("containers", containersNow().map(({ history: _history, ...rest }) => rest));
    if (tick % 25 === 0) {
      const open = alerts.find(a => a.id === 119);
      if (open) {
        open.count += 3;
        open.last_seen = Date.now();
        onEvent("alert", { ...open });
      }
    }
  }, 1000);
  return () => {
    clearInterval(timer);
    emitters.delete(onEvent);
  };
}

function simulateRun(kind: ReportKind): string {
  const id = `run_${Math.floor(Date.now() / 1000).toString(16).slice(-4)}`;
  const started = Date.now();
  const record: RunRecord = { run: { id, trigger: "manual", kind, status: "running", started_at: started, finished_at: null, model: ai.model, steps_count: 0, error: null, report_id: null, conversation_id: `c_${id}` }, steps: [] };
  runs.unshift(record);
  ai.running = id;
  const planned = stepsFor(id, started, kind);
  emit("agent", { run_id: id, conversation_id: `c_${id}`, status: "running", step: null });
  planned.forEach((step, index) => {
    setTimeout(() => {
      const live = { ...step, ts: Date.now() };
      record.steps.push(live);
      record.run.steps_count = record.steps.length;
      emit("agent", { run_id: id, conversation_id: `c_${id}`, status: "running", step: live });
      if (index === planned.length - 1) {
        setTimeout(() => {
          const reportId = Math.max(...reportSummaries.map(r => r.id)) + 1;
          const summary: ReportSummary = { id: reportId, kind, created_at: Date.now(), health_score: 66, title: "手动巡检", summary: diagnoses[57].summary, generated_by: "ai", model: ai.model, run_id: id };
          diagnoses[reportId] = { ...diagnoses[57], health_score: 66 };
          reportSummaries.unshift(summary);
          Object.assign(record.run, { status: "succeeded", finished_at: Date.now(), report_id: reportId });
          ai.running = null;
          ai.runs_today += 1;
          emit("agent", { run_id: id, conversation_id: `c_${id}`, status: "succeeded", step: null });
          emit("report", summary);
        }, 1500);
      }
    }, 1500 * (index + 1));
  });
  return id;
}

// Settings

const providers: Provider[] = [
  { id: "p1a2b3c4d", name: "OpenAI 中转", source: "db", api_format: "responses", base_url: "https://relay.example.com/v1", auth: "api_key", default_model: "gpt-5.2", has_key: true, updated_at: BOOT - DAY },
  { id: "default", name: "default", source: "config", api_format: "messages", base_url: "https://api.anthropic.com/v1", auth: "api_key", default_model: "claude-sonnet-5-5", has_key: true, key_env: "TSM_LLM_API_KEY", updated_at: null },
];
let routes: Route[] = [
  { kind: "default", provider: "default", model: "", effort: "" },
  { kind: "chat", provider: "p1a2b3c4d", model: "gpt-5.2", effort: "low" },
  { kind: "daily", provider: "default", model: "", effort: "high" },
];
const TASK_KINDS: [string, string][] = [
  ["default", "默认"], ["hourly", "小时巡检"], ["daily", "每日运维简报"], ["incident", "异常事件分析"], ["audit", "深度审计"],
  ["chat", "对话"], ["log_scan", "日志扫描"], ["security_check", "安全体检"], ["package_advice", "包更新建议"], ["prompt_gen", "提示词生成"],
];

function resolve(kind: string): ResolvedModel | null {
  const route = routes.find(r => r.kind === kind) ?? routes.find(r => r.kind === "default");
  const provider = route && providers.find(p => p.id === route.provider);
  if (!route || !provider) return null;
  const model = route.model || provider.default_model;
  return model ? { provider: provider.id, source: provider.source, api_format: provider.api_format, base_url: provider.base_url, model, auth: provider.auth, effort: route.effort } : null;
}

function routing(): RoutingResponse {
  return {
    kinds: TASK_KINDS.map(([kind, label]) => ({ kind, label, resolved: resolve(kind) })),
    efforts: ["", "none", "minimal", "low", "medium", "high", "xhigh", "max"],
    routes: routes.map(r => ({ ...r })),
  };
}

// Conversations

interface ChatMeta { id: string; title: string; context: Conversation["context"]; created_at: number }
const chats: ChatMeta[] = [
  { id: "c_chat1", title: "php-fpm 为什么频繁重启", context: null, created_at: Date.now() - 2 * HOUR },
];
(() => {
  const started = Date.now() - 2 * HOUR + 5_000;
  const id = "run_chat1";
  runs.push({
    run: { id, trigger: "user", kind: "chat", status: "succeeded", started_at: started, finished_at: started + 21_000, model: "gpt-5.2", steps_count: 4, error: null, report_id: null, conversation_id: "c_chat1" },
    steps: [
      { seq: 1, ts: started, kind: "user", tool: null, input: null, output: null, text: "php-fpm 为什么频繁重启？" },
      { seq: 2, ts: started + 4_000, kind: "tool_call", tool: "list_containers", input: {}, output: null, text: null },
      { seq: 3, ts: started + 4_300, kind: "tool_result", tool: "list_containers", input: null, output: { containers: [{ name: "php-fpm", restart_count: 14, oom_killed: true }] }, text: null },
      { seq: 4, ts: started + 21_000, kind: "message", tool: null, input: null, output: null, text: "php-fpm 在过去 6 小时重启了 14 次，最近一次是 OOM：容器内存上限 512 MiB，而 pm.max_children = 32、单进程峰值约 40 MiB。\n\n建议：\n1. 把 pm.max_children 调到 10 左右，或把内存上限提高到 1.5 GiB；\n2. 打开 slowlog 定位占内存的请求。" },
    ],
  });
})();

function conversationList(kind: "chat" | "task" | ""): Conversation[] {
  const byConv = new Map<string, RunRecord[]>();
  for (const r of runs) {
    const cid = r.run.conversation_id ?? `c_${r.run.id}`;
    byConv.set(cid, [...(byConv.get(cid) ?? []), r]);
  }
  const list: Conversation[] = [];
  for (const chat of chats) {
    const rs = (byConv.get(chat.id) ?? []).sort((a, b) => a.run.started_at - b.run.started_at);
    const last = rs.at(-1);
    list.push({ id: chat.id, title: chat.title, kind: "chat", context: chat.context, created_at: chat.created_at, updated_at: last?.run.started_at ?? chat.created_at, last_status: last?.run.status ?? null, runs: rs.length });
    byConv.delete(chat.id);
  }
  for (const [cid, rs] of byConv) {
    const run = rs[0].run;
    list.push({ id: cid, title: `${run.kind === "chat" ? "对话" : reportTitle(run.kind)} · ${new Date(run.started_at).toLocaleString("zh-CN", { hour12: false })}`, kind: run.kind, context: null, created_at: run.started_at, updated_at: run.finished_at ?? run.started_at, last_status: run.status, runs: rs.length });
  }
  return list
    .filter(c => !kind || (kind === "chat" ? c.kind === "chat" : c.kind !== "chat"))
    .sort((a, b) => b.updated_at - a.updated_at);
}

function reportTitle(kind: string): string {
  return ({ hourly: "小时巡检", daily: "每日运维简报", incident: "异常事件分析", audit: "深度审计" } as Record<string, string>)[kind] ?? kind;
}

function conversationDetail(id: string): ConversationDetail | null {
  const conv = conversationList("").find(c => c.id === id);
  if (!conv) return null;
  const rs = runs.filter(r => (r.run.conversation_id ?? `c_${r.run.id}`) === id).sort((a, b) => a.run.started_at - b.run.started_at);
  return { ...conv, runs: rs.map(r => ({ ...r.run, steps: r.steps.map(s => ({ ...s })) })) };
}

const ANSWER = "根据最近一小时的数据：CPU 平均 41%，内存 68%，没有持续超过阈值的指标。\n\n值得注意的是 php-error 日志的错误率是基线的 8 倍，主要模板是 `PDOException: SQLSTATE[HY000] [2002]`，说明应用连不上数据库。建议先检查 mysql 容器状态和连接数上限。";

function simulateChat(conversationId: string, text: string): string {
  const id = `run_${Math.random().toString(16).slice(2, 8)}`;
  const started = Date.now();
  const record: RunRecord = { run: { id, trigger: "user", kind: "chat", status: "running", started_at: started, finished_at: null, model: "gpt-5.2", steps_count: 1, error: null, report_id: null, conversation_id: conversationId }, steps: [] };
  const step = (kind: "user" | "tool_call" | "tool_result" | "message", extra: Partial<{ tool: string; input: unknown; output: unknown; text: string }>) => {
    const s = { seq: record.steps.length + 1, ts: Date.now(), kind, tool: extra.tool ?? null, input: extra.input ?? null, output: extra.output ?? null, text: extra.text ?? null };
    record.steps.push(s);
    record.run.steps_count = record.steps.length;
    emit("agent", { run_id: id, conversation_id: conversationId, status: "running", step: s });
  };
  runs.push(record);
  const chat = chats.find(c => c.id === conversationId);
  if (chat && chat.title === "新对话") chat.title = text.slice(0, 30);
  step("user", { text });
  setTimeout(() => step("tool_call", { tool: "get_host_metrics", input: { range: "1h" } }), 600);
  setTimeout(() => step("tool_result", { tool: "get_host_metrics", output: { cpu_avg: 41.2, mem_avg: 68.4 } }), 900);
  const parts = ANSWER.match(/.{1,6}/gsu) ?? [ANSWER];
  parts.forEach((part, i) => setTimeout(() => {
    if (record.run.status !== "running") return;
    emit("agent_delta", { run_id: id, conversation_id: conversationId, text: part });
  }, 1200 + i * 60));
  setTimeout(() => {
    if (record.run.status !== "running") return;
    step("message", { text: ANSWER });
    Object.assign(record.run, { status: "succeeded", finished_at: Date.now() });
    emit("agent", { run_id: id, conversation_id: conversationId, status: "succeeded", step: null });
  }, 1400 + parts.length * 60);
  return id;
}

// Tasks and prompts

const prompts: Prompt[] = [
  { id: "builtin:linux_check", name: "Linux 系统健康检查", description: "CPU、内存、交换、磁盘与 I/O、负载、网络、监听端口与容器的全面体检", body: "任务：Linux 系统健康检查。依次检查并给出结论：\n1. CPU 使用率与负载……", builtin: true, route_kind: "default", updated_at: null },
  { id: "builtin:security_check", name: "每日本机安全体检", description: "端口暴露、SSH 配置、登录爆破、待装安全更新、内核参数基线", body: "任务：每日本机安全体检。基于安全发现、监听端口和认证日志模板，检查……", builtin: true, route_kind: "security_check", updated_at: null },
  { id: "builtin:log_scan", name: "日志扫描", description: "扫描新出现或增长最快的错误模板、慢日志与突增来源", body: "任务：日志扫描（触发原因：{trigger}）。查看各日志源的错误率趋势……", builtin: true, route_kind: "log_scan", updated_at: null },
  { id: "builtin:package_advice", name: "包更新建议", description: "评估待升级软件包的风险与升级顺序", body: "任务：软件包更新评估……", builtin: true, route_kind: "package_advice", updated_at: null },
  { id: "builtin:hourly", name: "小时巡检（系统内置）", description: "每小时自动运行的快速巡检", body: "任务：小时巡检。快速判断过去一小时是否有异常趋势……", builtin: true, route_kind: "hourly", updated_at: null },
  { id: "builtin:daily", name: "每日运维简报（系统内置）", description: "每天定时生成的运维简报", body: "任务：生成每日运维简报……", builtin: true, route_kind: "daily", updated_at: null },
  { id: "builtin:incident", name: "异常事件分析（系统内置）", description: "日志或错误突增时自动运行", body: "任务：异常事件分析（触发原因：{trigger}）……", builtin: true, route_kind: "incident", updated_at: null },
  { id: "builtin:audit", name: "深度审计（系统内置）", description: "夜间空闲窗口内的深度审计", body: "任务：空闲窗口深度审计……", builtin: true, route_kind: "audit", updated_at: null },
  { id: "u_nginx5xx", name: "Nginx 5xx 排查", description: "统计 5xx 的接口与上游", body: "任务：排查 Nginx 5xx。按接口和上游统计过去一小时的 5xx……", builtin: false, route_kind: "default", updated_at: BOOT - DAY },
];
const tasks: Task[] = [
  { id: "t_security_check", name: "每日本机安全体检", enabled: true, builtin: true, trigger: { type: "daily", at: "03:30" }, prompt_id: "builtin:security_check", route_kind: "security_check", last_fired_at: BOOT - 7 * HOUR, cursor: null, last_run_id: null, created_at: BOOT - 10 * DAY, updated_at: BOOT - 10 * DAY },
  { id: "t_log_scan", name: "日志定时扫描", enabled: false, builtin: true, trigger: { type: "interval", every_mins: 360 }, prompt_id: "builtin:log_scan", route_kind: "log_scan", last_fired_at: null, cursor: null, last_run_id: null, created_at: BOOT - 10 * DAY, updated_at: BOOT - 10 * DAY },
  { id: "t_nginx", name: "Nginx 错误超阈值排查", enabled: true, builtin: false, trigger: { type: "log_threshold", source: "nginx-error", metric: "errors", count: 200, min_interval_mins: 60 }, prompt_id: "u_nginx5xx", route_kind: "log_scan", last_fired_at: BOOT - 3 * HOUR, cursor: null, last_run_id: null, created_at: BOOT - 2 * DAY, updated_at: BOOT - 2 * DAY },
];
const systemJobs: SystemJob[] = [
  { id: "system:hourly", name: "小时巡检", enabled: true, trigger: "每小时整点", prompt_id: "builtin:hourly", route_kind: "hourly" },
  { id: "system:daily", name: "每日运维简报", enabled: true, trigger: "每天 04:00", prompt_id: "builtin:daily", route_kind: "daily" },
  { id: "system:incident", name: "异常事件分析", enabled: true, trigger: "日志错误突增（基线 3 倍且每分钟 ≥ 20）", prompt_id: "builtin:incident", route_kind: "incident" },
  { id: "system:audit", name: "深度审计", enabled: true, trigger: "空闲窗口 01:00-05:00（CPU < 30%）", prompt_id: "builtin:audit", route_kind: "audit" },
];

// Notification channels

const channels: NotifyChannel[] = [
  { id: "config:telegram", name: "Telegram（配置文件）", kind: "telegram", source: "config", enabled: true, min_severity: "critical", events: ["alert", "report", "digest"], config: { chat_id: "-1001234567", api_base: "https://api.telegram.org", bot_enabled: false, allowed_user_ids: [] }, has_secret: true },
  { id: "n_mail01", name: "运维邮箱", kind: "email", source: "db", enabled: true, min_severity: "critical", events: ["alert", "digest"], config: { host: "smtp.example.com", port: 587, security: "starttls", username: "monitor@example.com", from: "TServerMonitor <monitor@example.com>", to: ["ops@example.com"] }, has_secret: true },
];

function alertAction(id: number, patch: Partial<Alert>): Promise<Alert> {
  const a = alerts.find(x => x.id === id);
  if (!a) return Promise.reject(new ApiError(404, "alert not found"));
  Object.assign(a, patch);
  emit("alert", { ...a });
  return delay({ ...a });
}

// Package updates

const packageReport: PackagesResponse = {
  checked_at: BOOT - 2 * HOUR, managers: ["apt"], errors: [], in_container: false,
  packages: [
    { manager: "apt", name: "openssl", current: "3.0.2-0ubuntu1.15", available: "3.0.2-0ubuntu1.18", source: "Ubuntu:22.04/jammy-security", security: true },
    { manager: "apt", name: "openssh-server", current: "1:8.9p1-3ubuntu0.10", available: "1:8.9p1-3ubuntu0.13", source: "Ubuntu:22.04/jammy-security", security: true },
    { manager: "apt", name: "linux-image-generic", current: "5.15.0.119.119", available: "5.15.0.125.125", source: "Ubuntu:22.04/jammy-security", security: true },
    { manager: "apt", name: "nginx", current: "1.18.0-6ubuntu14.4", available: "1.18.0-6ubuntu14.5", source: "Ubuntu:22.04/jammy-updates", security: false },
    { manager: "apt", name: "tzdata", current: "2024a-0ubuntu0.22.04", available: "2024b-0ubuntu0.22.04", source: "Ubuntu:22.04/jammy-updates", security: false },
  ],
};
const packageJobs: PackageJob[] = [
  { id: 1, op: "refresh", packages: [], status: "succeeded", exit_code: 0, log: "$ apt-get update\nHit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\nReading package lists...\n", started_at: BOOT - 2 * HOUR, finished_at: BOOT - 2 * HOUR + 9_000 },
];

function simulateJob(op: PackageOp, names: string[]): number {
  const id = Math.max(0, ...packageJobs.map(j => j.id)) + 1;
  const job: PackageJob = { id, op, packages: names, status: "running", exit_code: null, log: "", started_at: Date.now(), finished_at: null };
  packageJobs.unshift(job);
  const targets = op === "upgrade_packages" ? names : op === "upgrade_security" ? packageReport.packages.filter(p => p.security).map(p => p.name) : packageReport.packages.map(p => p.name);
  const lines = op === "refresh"
    ? ["$ apt-get update", "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease", "Get:2 http://security.ubuntu.com/ubuntu jammy-security InRelease [129 kB]", "Reading package lists..."]
    : [`$ apt-get -y --only-upgrade install -- ${targets.join(" ")}`, "Reading package lists...", ...targets.map(t => `Unpacking ${t} ...`), ...targets.map(t => `Setting up ${t} ...`)];
  emit("package_job", { id, status: "running", line: null });
  lines.forEach((line, i) => setTimeout(() => {
    job.log += `${line}\n`;
    emit("package_job", { id, status: "running", line });
  }, 500 * (i + 1)));
  setTimeout(() => {
    Object.assign(job, { status: "succeeded", exit_code: 0, finished_at: Date.now() });
    if (op !== "refresh") packageReport.packages = packageReport.packages.filter(p => !targets.includes(p.name));
    packageReport.checked_at = Date.now();
    emit("package_job", { id, status: "succeeded", line: null });
  }, 500 * (lines.length + 1));
  return id;
}

// API

function snapshot(): Snapshot {
  const host = hostAt(Date.now());
  const list = containersNow();
  const open = alerts.filter(a => a.status === "open");
  const latest = reportSummaries[0] ?? null;
  return {
    generated_at: Date.now(),
    host,
    health: { score: 68, dimensions: dims(74, 69, 72, 35, 52, 50, 62), source: "ai" },
    mode: { ...mode },
    containers: {
      total: list.length,
      running: list.filter(c => c.state === "running").length,
      unhealthy: list.filter(c => c.health === "unhealthy").length,
      restart_loops: list.filter(c => c.restart_loop).length,
      oom: list.filter(c => c.oom_killed).length,
    },
    alerts_open: {
      critical: open.filter(a => a.severity === "critical").length,
      warning: open.filter(a => a.severity === "warning").length,
      info: open.filter(a => a.severity === "info").length,
    },
    ai: { ...ai },
    latest_report: latest,
  };
}

// Accounts (mock): starts with the setup wizard; any setup code is accepted.
const mockUsers: (AccountUser & { password: string })[] = [];
let mockSignedIn: number | null = null;
const mockTokens: ApiTokenRecord[] = [];
const mockSessions = (): SessionView[] => [
  { id: "s-this", created_at: BOOT, last_seen: Date.now(), expires_at: Date.now() + 7 * DAY, remote: "127.0.0.1", user_agent: navigator.userAgent, current: true },
  { id: "s-phone", created_at: BOOT - DAY, last_seen: Date.now() - 3 * HOUR, expires_at: Date.now() + 5 * DAY, remote: "203.0.113.7", user_agent: "Mozilla/5.0 (iPhone) Safari/605.1", current: false },
];
const sudoGate = <T,>(value: T): Promise<T> =>
  withSudo(() => (mockAuth.sudoUntil > Date.now() ? delay(value) : Promise.reject(new ApiError(403, "此操作需要先确认密码", "sudo_required"))));
const authApi: Pick<Api, "authState" | "setup" | "login" | "logout" | "sudo" | "changePassword" | "sessions" | "revokeSession" | "users" | "createUser" | "deleteUser" | "tokens" | "createToken" | "revokeToken"> = {
  authState: () => {
    const u = mockUsers.find(x => x.id === mockSignedIn);
    const state: AuthState = { setup_required: mockUsers.length === 0, authenticated: Boolean(u), kind: u ? "session" : null, user: u ? { id: u.id, username: u.username } : null, sudo_until: mockAuth.sudoUntil };
    return delay(state, 120);
  },
  setup: (code, username, password) => {
    if (!code.trim()) return Promise.reject(new ApiError(400, "setup 码不正确（见服务器上的 setup-code 文件或启动日志）"));
    if (password.length < 10) return Promise.reject(new ApiError(400, "密码至少 10 位"));
    mockUsers.push({ id: 1, username, password, created_at: Date.now(), last_login_at: Date.now() });
    mockSignedIn = 1;
    return delay({ ok: true as const });
  },
  login: (username, password) => {
    const u = mockUsers.find(x => x.username === username && x.password === password);
    if (!u) return Promise.reject(new ApiError(401, "用户名或密码不正确", "bad_credentials"));
    mockSignedIn = u.id;
    u.last_login_at = Date.now();
    return delay({ user: { id: u.id, username: u.username } });
  },
  logout: () => {
    mockSignedIn = null;
    mockAuth.sudoUntil = 0;
    return delay({ ok: true as const });
  },
  sudo: password => {
    const u = mockUsers.find(x => x.id === mockSignedIn);
    if (!u || u.password !== password) return Promise.reject(new ApiError(400, "密码不正确"));
    mockAuth.sudoUntil = Date.now() + 10 * MIN;
    return delay({ sudo_until: mockAuth.sudoUntil });
  },
  changePassword: (current, next) => {
    const u = mockUsers.find(x => x.id === mockSignedIn);
    if (!u || u.password !== current) return Promise.reject(new ApiError(400, "当前密码不正确"));
    u.password = next;
    return delay({ ok: true as const });
  },
  sessions: () => delay(mockSessions()),
  revokeSession: () => delay({ ok: true as const }),
  users: () => delay(mockUsers.map(({ password: _p, ...u }) => u)),
  createUser: (username, password) => sudoGate(null).then(() => {
    const id = Math.max(0, ...mockUsers.map(u => u.id)) + 1;
    mockUsers.push({ id, username, password, created_at: Date.now(), last_login_at: null });
    return { id };
  }),
  deleteUser: id => sudoGate(null).then(() => {
    const i = mockUsers.findIndex(u => u.id === id);
    if (i >= 0) mockUsers.splice(i, 1);
    return { ok: true as const };
  }),
  tokens: () => delay(mockTokens),
  createToken: (name, scope, expiresDays) => sudoGate(null).then(() => {
    const token = `tsm_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
    const record: ApiTokenRecord = { id: mockTokens.length + 1, name, prefix: token.slice(0, 10), scope, created_at: Date.now(), expires_at: expiresDays ? Date.now() + expiresDays * DAY : null, last_used_at: null, revoked_at: null };
    mockTokens.unshift(record);
    return { token, record };
  }),
  revokeToken: id => sudoGate(null).then(() => {
    const t = mockTokens.find(x => x.id === id);
    if (t) t.revoked_at = Date.now();
    return { ok: true as const };
  }),
};

export const mockApi: Api = {
  ...opsMock(emit),
  ...authApi,
  status: () => delay({
    version: "0.1.0-dev", platform: "linux-x86_64", started_at: BOOT - 2 * DAY, mode: { ...mode }, ai: { ...ai },
    collectors: {
      host: { ok: true, detail: null }, docker: { ok: true, detail: null }, logs: { ok: true, detail: null },
      security: { ok: true, detail: null }, mysql: { ok: true, detail: null }, postgres: { ok: false, detail: "connection refused" },
    },
  }),
  snapshot: () => delay(snapshot()),
  metrics: range => delay(metricsFor(range), 400),
  containers: () => delay(containersNow()),
  containerLogs: (id, tail = 200) => {
    try {
      return delay({ lines: containerLogs(id, tail) });
    } catch (error) {
      return Promise.reject(error);
    }
  },
  logSources: () => delay(logSources),
  logRates: () => delay(logRates()),
  logClusters: (filter = {}) => delay(logClusters(filter)),
  dailyErrors: (days = 365) => delay(dailyErrors(days)),
  findings: (includeResolved = false) => delay(findings.filter(f => includeResolved || !f.resolved)),
  ports: () => delay(ports),
  db: () => delay(dbStatus()),
  alerts: (status = "open", limit = 100) => delay(alerts.filter(a => status === "all" || a.status === "open").slice(0, limit)),
  reports: (kind = "", limit = 50) => delay(reportSummaries.filter(r => !kind || r.kind === kind).slice(0, limit)),
  latestReport: kind => {
    const found = reportSummaries.find(r => !kind || r.kind === kind);
    return found ? delay<Report>({ ...found, body: diagnoses[found.id] }) : Promise.reject(new ApiError(404, "no report"));
  },
  report: id => {
    const found = reportSummaries.find(r => r.id === id);
    return found ? delay<Report>({ ...found, body: diagnoses[found.id] }) : Promise.reject(new ApiError(404, "report not found"));
  },
  agentRuns: (limit = 50) => delay(runs.slice(0, limit).map(r => r.run)),
  agentRun: id => {
    const found = runs.find(r => r.run.id === id);
    return found ? delay<AgentRunDetail>({ ...found.run, steps: found.steps }) : Promise.reject(new ApiError(404, "run not found"));
  },
  trigger: kind => {
    if (ai.running) return new Promise((_, reject) => setTimeout(() => reject(new ApiError(409, "a run is already in progress")), 300));
    return delay({ run_id: simulateRun(kind) });
  },
  providers: () => delay({ providers: providers.map(p => ({ ...p })), key_storage: "file" as const }),
  createProvider: input => {
    if (!input.name?.trim() || !input.base_url?.trim()) return Promise.reject(new ApiError(400, "名称和 base_url 不能为空"));
    const id = `p${Math.random().toString(16).slice(2, 10)}`;
    providers.unshift({
      id, name: input.name.trim(), source: "db", api_format: input.api_format ?? "responses", base_url: input.base_url.trim(),
      auth: input.auth ?? "api_key", default_model: input.default_model ?? "", has_key: Boolean(input.api_key), updated_at: Date.now(),
    });
    return delay({ id });
  },
  updateProvider: (id, input) => {
    const p = providers.find(x => x.id === id && x.source === "db");
    if (!p) return Promise.reject(new ApiError(404, "provider not found"));
    if (input.base_url && input.base_url !== p.base_url && p.has_key && input.api_key === undefined) {
      return Promise.reject(new ApiError(400, "修改 base_url 时必须重新填写密钥"));
    }
    const { api_key, ...rest } = input;
    Object.assign(p, rest, { updated_at: Date.now() });
    if (api_key !== undefined) p.has_key = api_key !== "";
    return delay({ id });
  },
  deleteProvider: id => {
    const index = providers.findIndex(x => x.id === id && x.source === "db");
    if (index < 0) return Promise.reject(new ApiError(404, "provider not found"));
    providers.splice(index, 1);
    routes = routes.filter(r => r.provider !== id);
    return delay({ ok: true as const });
  },
  listModels: req => req.base_url?.includes("fail")
    ? Promise.reject(new ApiError(400, "模型列表接口返回 HTTP 404"))
    : delay({ models: req.api_format === "messages" ? ["claude-haiku-5-5", "claude-opus-5-5", "claude-sonnet-5-5"] : ["gpt-5.2", "gpt-5.2-mini", "o4"] }, 600),
  routing: () => delay(routing()),
  conversations: (kind = "", limit = 100) => delay(conversationList(kind).slice(0, limit)),
  conversation: id => {
    const found = conversationDetail(id);
    return found ? delay(found) : Promise.reject(new ApiError(404, "conversation not found"));
  },
  createConversation: input => {
    const id = `c_${Math.random().toString(16).slice(2, 10)}`;
    chats.unshift({ id, title: input.title || "新对话", context: input.context ?? null, created_at: Date.now() });
    return delay({ id, run_id: input.message ? simulateChat(id, input.message) : null });
  },
  sendMessage: (id, text) => {
    if (runs.some(r => r.run.conversation_id === id && r.run.status === "running")) return Promise.reject(new ApiError(409, "a run is already in progress"));
    if (!conversationDetail(id)) return Promise.reject(new ApiError(404, "conversation not found"));
    return delay({ run_id: simulateChat(id, text) }, 150);
  },
  deleteConversation: id => {
    const index = chats.findIndex(c => c.id === id);
    if (index < 0) return Promise.reject(new ApiError(400, "只能删除手动发起的对话"));
    chats.splice(index, 1);
    for (let i = runs.length - 1; i >= 0; i--) if (runs[i].run.conversation_id === id) runs.splice(i, 1);
    return delay({ ok: true as const });
  },
  tasks: () => delay({ tasks: tasks.map(t => ({ ...t })), system: systemJobs }),
  createTask: input => {
    if (!input.name?.trim() || !input.trigger || !input.prompt_id) return Promise.reject(new ApiError(400, "名称、触发方式和提示词不能为空"));
    const id = `t_${Math.random().toString(16).slice(2, 10)}`;
    tasks.push({ id, name: input.name.trim(), enabled: input.enabled ?? true, builtin: false, trigger: input.trigger, prompt_id: input.prompt_id, route_kind: input.route_kind ?? "default", last_fired_at: null, cursor: Date.now(), last_run_id: null, created_at: Date.now(), updated_at: Date.now() });
    return delay({ id });
  },
  updateTask: (id, input) => {
    const t = tasks.find(x => x.id === id);
    if (!t) return Promise.reject(new ApiError(404, "task not found"));
    Object.assign(t, input, { updated_at: Date.now() });
    return delay({ id });
  },
  deleteTask: id => {
    const index = tasks.findIndex(x => x.id === id);
    if (index < 0) return Promise.reject(new ApiError(404, "task not found"));
    if (tasks[index].builtin) return Promise.reject(new ApiError(400, "内置任务不能删除，可以停用"));
    tasks.splice(index, 1);
    return delay({ ok: true as const });
  },
  runTask: id => {
    const t = tasks.find(x => x.id === id);
    if (!t) return Promise.reject(new ApiError(404, "task not found"));
    if (ai.running) return delay({ run_id: null, deferred: true });
    t.last_fired_at = Date.now();
    const runId = simulateRun("custom");
    t.last_run_id = runId;
    return delay({ run_id: runId, deferred: false });
  },
  prompts: () => delay(prompts.map(p => ({ ...p }))),
  createPrompt: input => {
    if (!input.name?.trim() || !input.body?.trim()) return Promise.reject(new ApiError(400, "名称和提示词不能为空"));
    const id = `u_${Math.random().toString(16).slice(2, 12)}`;
    prompts.push({ id, name: input.name.trim(), description: input.description ?? "", body: input.body.trim(), builtin: false, route_kind: "default", updated_at: Date.now() });
    return delay({ id });
  },
  updatePrompt: (id, input) => {
    const p = prompts.find(x => x.id === id);
    if (!p) return Promise.reject(new ApiError(404, "prompt not found"));
    if (p.builtin) return Promise.reject(new ApiError(400, "内置提示词只读，可以复制后修改"));
    Object.assign(p, input, { updated_at: Date.now() });
    return delay({ id });
  },
  deletePrompt: id => {
    const index = prompts.findIndex(x => x.id === id);
    if (index < 0) return Promise.reject(new ApiError(404, "prompt not found"));
    if (prompts[index].builtin) return Promise.reject(new ApiError(400, "内置提示词不能删除"));
    if (tasks.some(t => t.prompt_id === id)) return Promise.reject(new ApiError(400, "有自动任务正在使用这个提示词，请先修改或删除这些任务"));
    prompts.splice(index, 1);
    return delay({ ok: true as const });
  },
  generatePrompt: description => delay({ body: `任务：${description}。\n1. 查看相关日志源的错误率趋势与主要错误模板；\n2. 结合主机与容器指标判断是否存在资源瓶颈；\n3. 对发现的问题给出根因判断和具体处理建议（命令或配置项）。没有明显问题时简要说明即可。` }, 1500),
  ackAlert: id => alertAction(id, { acked_at: Date.now() }),
  silenceAlert: (id, minutes) => alertAction(id, { silenced_until: minutes > 0 ? Date.now() + minutes * MIN : null }),
  closeAlert: id => alertAction(id, { status: "resolved", acked_at: Date.now() }),
  channels: () => delay({ channels: channels.map(c => ({ ...c })), key_storage: "file" as const }),
  createChannel: input => {
    if (!input.kind || !input.name?.trim() || !input.config) return Promise.reject(new ApiError(400, "名称和配置不能为空"));
    const id = `n_${Math.random().toString(16).slice(2, 10)}`;
    channels.push({ id, name: input.name.trim(), kind: input.kind, source: "db", enabled: input.enabled ?? true, min_severity: input.min_severity ?? "critical", events: input.events ?? ["alert", "digest"], config: input.config, has_secret: Boolean(input.secret) });
    return delay({ id });
  },
  updateChannel: (id, input) => {
    const c = channels.find(x => x.id === id && x.source === "db");
    if (!c) return Promise.reject(new ApiError(404, "channel not found"));
    const { secret, ...rest } = input;
    Object.assign(c, rest);
    if (secret !== undefined) c.has_secret = secret !== "";
    return delay({ id });
  },
  deleteChannel: id => {
    const index = channels.findIndex(x => x.id === id && x.source === "db");
    if (index < 0) return Promise.reject(new ApiError(404, "channel not found"));
    channels.splice(index, 1);
    return delay({ ok: true as const });
  },
  access: (window = 15) => {
    const now = Math.floor(Date.now() / MIN) * MIN;
    const series = Array.from({ length: window }, (_, i) => {
      const requests = Math.round(820 + 180 * Math.sin(i / 3) + Math.random() * 90);
      return { ts: now - (window - 1 - i) * MIN, requests, s4xx: Math.round(requests * 0.03), s5xx: i > window - 4 ? Math.round(requests * 0.06) : Math.round(requests * 0.004) };
    });
    const requests = series.reduce((n, p) => n + p.requests, 0);
    const s4 = series.reduce((n, p) => n + p.s4xx, 0);
    const s5 = series.reduce((n, p) => n + p.s5xx, 0);
    return delay({
      sources: ["nginx-access"],
      stats: {
        window_mins: window, requests, requests_per_min: requests / window,
        status: [Math.round((requests - s4 - s5) * 0.93), Math.round((requests - s4 - s5) * 0.07), s4, s5],
        error_rate_5xx: s5 / requests, bytes: requests * 5_400, series,
        top_paths: [
          { path: "GET /api/orders/<n>", requests: Math.round(requests * 0.31), s5xx: Math.round(s5 * 0.7) },
          { path: "GET /static/<*>", requests: Math.round(requests * 0.22), s5xx: 0 },
          { path: "POST /api/login", requests: Math.round(requests * 0.09), s5xx: Math.round(s5 * 0.2) },
          { path: "GET /healthz", requests: Math.round(requests * 0.05), s5xx: 0 },
        ],
        top_ips: [
          { ip: "203.0.113.42", requests: Math.round(requests * 0.12), s4xx: 14, scan: 0 },
          { ip: "198.51.100.7", requests: Math.round(requests * 0.08), s4xx: 3, scan: 0 },
          { ip: "10.0.3.15", requests: Math.round(requests * 0.05), s4xx: 0, scan: 0 },
        ],
        latency: { p50_ms: 50, p95_ms: 500, p99_ms: 1000, samples: requests },
        slow_paths: [
          { path: "GET /api/reports/export", requests: 18, s5xx: 1, avg_ms: 3_420 },
          { path: "POST /api/checkout", requests: 140, s5xx: 2, avg_ms: 1_180 },
        ],
        top_hosts: [{ key: "shop.example.com", requests: Math.round(requests * 0.8) }, { key: "api.example.com", requests: Math.round(requests * 0.2) }],
        user_agents: [{ key: "browser", requests: Math.round(requests * 0.72) }, { key: "bot", requests: Math.round(requests * 0.14) }, { key: "tool", requests: Math.round(requests * 0.13) }, { key: "scanner", requests: Math.round(requests * 0.01) }],
        suspicious: [{ ip: "192.0.2.66", requests: 212, s4xx: 205, scan: 190 }],
      },
    }, 250);
  },
  packages: () => delay({ ...packageReport, packages: [...packageReport.packages], updater: { available: true, socket: "/run/tsmonitor-updater/updater.sock" } }),
  checkPackages: () => {
    packageReport.checked_at = Date.now();
    return delay({ ...packageReport, packages: [...packageReport.packages] }, 900);
  },
  packageJobs: () => delay(packageJobs.map(({ log: _log, ...j }) => j)),
  packageJob: id => {
    const j = packageJobs.find(x => x.id === id);
    return j ? delay({ ...j }) : Promise.reject(new ApiError(404, "job not found"));
  },
  startPackageJob: (op, names = []) => {
    if (packageJobs.some(j => j.status === "running")) return Promise.reject(new ApiError(400, "已有更新任务在运行"));
    return delay({ id: simulateJob(op, names) });
  },
  testChannel: id => (channels.some(c => c.id === id) ? delay({ ok: true as const }, 800) : Promise.reject(new ApiError(404, "channel not found"))),
  cancelRun: runId => {
    const r = runs.find(x => x.run.id === runId && x.run.status === "running");
    if (!r) return Promise.reject(new ApiError(404, "running run not found"));
    Object.assign(r.run, { status: "cancelled", finished_at: Date.now(), error: "已取消" });
    emit("agent", { run_id: runId, conversation_id: r.run.conversation_id, status: "cancelled", step: null });
    return delay({ ok: true as const });
  },
  saveRouting: next => {
    routes = next.map(r => ({ ...r }));
    return delay(routing());
  },
};
