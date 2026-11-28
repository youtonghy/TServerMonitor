// Mock of the management API (ops helper): stateful enough to click through every page.
// Never imported by production builds.
import { ApiError, withSudo, type Api } from "./client";
import type {
  AccessRange, AccessStats, AuditEntry, DockerImage, DockerInventory, DockerNetwork, DockerVolume, FirewallStatus,
  CertInfo, NginxFile, NginxFileEntry, NginxLogTail, NginxSiteDetail, NginxSites, NginxStatus, NginxVersions, OpsCapabilities, SiteSpec, OpsJob, OpsRead, PendingChange, SshConfig, SshKeys, SshSession,
  StreamEventMap, StreamEventName,
} from "./types";

type Emit = <K extends StreamEventName>(event: K, data: StreamEventMap[K]) => void;
const MIN = 60_000;
const delay = <T,>(value: T, ms = 150 + Math.random() * 250): Promise<T> =>
  new Promise(resolve => setTimeout(() => resolve(structuredClone(value)), ms));

const caps: OpsCapabilities = {
  available: true, reason: null, version: "0.1.0", dry_run: false, confirm_secs: 120,
  write_ready: true, write_reason: null,
  domains: {
    docker: { enabled: true, allow: ["start", "stop", "restart", "kill", "remove", "image_pull", "image_remove", "image_prune", "project"] },
    nginx: {
      enabled: true, allow: ["test", "reload", "site", "edit", "manage", "cert", "service", "install", "upgrade"], runtime: "auto",
      site_roots: ["/var/www"], cert_paths: ["/etc/letsencrypt", "/etc/ssl"],
      acme: { enabled: true, staging: false, custom_directory: false, renew_days: 30 },
    },
    firewall: { enabled: true, allow: ["add_rule", "delete_rule", "toggle"], backend: "ufw" },
    ssh: { enabled: true, allow: ["options", "key_add", "key_remove"] },
  },
};

const inventory: DockerInventory = {
  containers: [
    { id: "a1b2c3d4e5f6", name: "shop-web-1", image: "nginx:1.27", state: "running", status: "Up 3 days", project: "shop", service: "web", protected: false },
    { id: "b2c3d4e5f6a1", name: "shop-api-1", image: "ghcr.io/acme/shop-api:2.4.1", state: "running", status: "Up 3 days (healthy)", project: "shop", service: "api", protected: false },
    { id: "c3d4e5f6a1b2", name: "shop-db-1", image: "postgres:16", state: "running", status: "Up 3 days", project: "shop", service: "db", protected: false },
    { id: "d4e5f6a1b2c3", name: "worker", image: "ghcr.io/acme/worker:1.9", state: "exited", status: "Exited (1) 2 hours ago", project: null, service: null, protected: false },
    { id: "e5f6a1b2c3d4", name: "docker-proxy", image: "tecnativa/docker-socket-proxy:latest", state: "running", status: "Up 9 days", project: null, service: null, protected: true },
  ],
  projects: [],
};
const refreshProjects = () => {
  const by = new Map<string, DockerInventory["projects"][number]>();
  for (const c of inventory.containers) {
    if (!c.project) continue;
    const p = by.get(c.project) ?? { name: c.project, working_dir: `/srv/${c.project}`, services: [], containers: [], running: 0, total: 0 };
    if (c.service) p.services.push(c.service);
    p.containers.push(c.id);
    p.total += 1;
    if (c.state === "running") p.running += 1;
    by.set(c.project, p);
  }
  inventory.projects = [...by.values()];
};
refreshProjects();

let images: DockerImage[] = [
  { id: "3b25b682ea82", tags: ["nginx:1.27"], size: 192 * 1024 ** 2, created: Date.now() - 20 * 86_400_000, containers: 1, dangling: false },
  { id: "9f1c2d3e4a5b", tags: ["ghcr.io/acme/shop-api:2.4.1"], size: 412 * 1024 ** 2, created: Date.now() - 3 * 86_400_000, containers: 1, dangling: false },
  { id: "1a2b3c4d5e6f", tags: ["postgres:16"], size: 438 * 1024 ** 2, created: Date.now() - 40 * 86_400_000, containers: 1, dangling: false },
  { id: "7e8f9a0b1c2d", tags: [], size: 405 * 1024 ** 2, created: Date.now() - 9 * 86_400_000, containers: 0, dangling: true },
];
const volumes: DockerVolume[] = [
  { name: "shop_pgdata", driver: "local", project: "shop", in_use: true },
  { name: "old_cache", driver: "local", project: null, in_use: false },
];
const networks: DockerNetwork[] = [
  { id: "aa11bb22cc33", name: "bridge", driver: "bridge", scope: "local", internal: false },
  { id: "bb22cc33dd44", name: "shop_default", driver: "bridge", scope: "local", internal: false },
];

// nginx runtime. Start in another state with ?nginx_runtime=docker or ?nginx_runtime=none before the hash,
// e.g. http://localhost:5173/?nginx_runtime=none#/nginx (installing from "none" switches to docker).
const NGINX_MODULES = ["http_ssl_module", "http_v2_module", "http_v3_module", "http_realip_module", "http_gzip_static_module", "http_stub_status_module", "http_sub_module", "stream", "stream_ssl_module", "threads"];
const nginxDocker = (version: string, previous: string | null, uptimeSecs = 0): NginxStatus => ({
  runtime: "docker", configured_runtime: "auto", installed: true, running: true, version, modules: NGINX_MODULES,
  build: "built by gcc 12.2.0 (Debian 12.2.0-14); built with OpenSSL 3.0.15 3 Sep 2024", workers: 2,
  started_at: Math.floor(Date.now() / 1000) - uptimeSecs, service: null,
  container: { name: "tsmonitor-nginx", id: Math.random().toString(16).slice(2, 14), image: `nginx:${version}`, state: "running" },
  package: null, previous_image: previous, install_blockers: [], docker_available: true,
});
const nginxHost = (): NginxStatus => ({
  runtime: "host", configured_runtime: "auto", installed: true, running: true, version: "1.24.0", modules: NGINX_MODULES.filter(m => m !== "http_v3_module"),
  build: "built with OpenSSL 3.0.13 30 Jan 2024", workers: 4, started_at: Math.floor(Date.now() / 1000) - 3 * 86_400 - 5 * 3_600,
  service: "nginx.service", container: null, package: { manager: "apt", installed: "1.24.0-2ubuntu7.1", candidate: "1.24.0-2ubuntu7.3" },
  previous_image: null, install_blockers: [], docker_available: true,
});
const nginxNone = (): NginxStatus => ({
  runtime: "none", configured_runtime: "auto", installed: false, running: false, version: null, modules: [], build: null, workers: null,
  started_at: null, service: null, container: null, package: null, previous_image: null, install_blockers: [], docker_available: true,
});
const startRuntime = typeof location === "undefined" ? null : new URLSearchParams(location.search).get("nginx_runtime");
let nginx: NginxStatus = startRuntime === "docker" ? nginxDocker("1.26.3", null, 26 * 3_600) : startRuntime === "none" ? nginxNone() : nginxHost();
const nginxVersions: NginxVersions = {
  image: "nginx",
  versions: [
    { version: "1.29.1", channel: "mainline", latest: true },
    { version: "1.29.0", channel: "mainline", latest: false },
    { version: "1.28.0", channel: "stable", latest: true },
    { version: "1.27.5", channel: "mainline", latest: false },
    { version: "1.27.3", channel: "mainline", latest: false },
    { version: "1.26.3", channel: "stable", latest: false },
    { version: "1.26.2", channel: "stable", latest: false },
    { version: "1.24.0", channel: "stable", latest: false },
  ],
};
const nginxLog = (file: "error" | "access", lines: number): NginxLogTail => {
  const t = (minsAgo: number) => new Date(Date.now() - minsAgo * MIN).toISOString().replace("T", " ").slice(0, 19).replaceAll("-", "/");
  const all = file === "access"
    ? Array.from({ length: 320 }, (_, i) => {
      const paths = ["/", "/api/orders", "/static/app.js", "/wp-login.php", "/api/cart", "/.env"];
      const p = paths[i % paths.length];
      const code = p === "/.env" || p === "/wp-login.php" ? 404 : p === "/api/orders" && i % 7 === 0 ? 502 : 200;
      return `203.0.113.${(i * 7) % 250} - - [${t(320 - i)}] "GET ${p} HTTP/1.1" ${code} ${(i * 131) % 9000} "-" "Mozilla/5.0" 0.0${i % 9}`;
    })
    : [
      `${t(180)} [notice] 1#1: using the "epoll" event method`,
      `${t(180)} [notice] 1#1: start worker processes`,
      `${t(42)} [warn] 1234#1234: *881 an upstream response is buffered to a temporary file /var/cache/nginx/proxy_temp/1/00/0000000001 while reading upstream`,
      `${t(17)} [error] 1234#1234: *1022 connect() failed (111: Connection refused) while connecting to upstream, client: 203.0.113.7, server: api.example.com, request: "GET /api/orders HTTP/1.1", upstream: "http://127.0.0.1:3000/api/orders"`,
      `${t(3)} [error] 1234#1234: *1107 open() "/var/www/shop/.env" failed (2: No such file or directory), client: 198.51.100.23, server: shop.example.com, request: "GET /.env HTTP/1.1"`,
    ];
  return { path: `/var/log/nginx/${file}.log`, lines: all.slice(-lines), truncated: all.length > lines };
};

const files: Record<string, string> = {
  "nginx.conf": "user www-data;\nworker_processes auto;\n\nevents { worker_connections 1024; }\n\nhttp {\n    include mime.types;\n    log_format main '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" $request_time';\n    access_log /var/log/nginx/access.log main;\n    sendfile on;\n    keepalive_timeout 65;\n    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;\n}\n",
  "sites-available/shop": "server {\n    listen 80;\n    listen 443 ssl;\n    server_name shop.example.com www.shop.example.com;\n\n    ssl_certificate /etc/letsencrypt/live/shop/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/shop/privkey.pem;\n\n    location / {\n        proxy_pass http://127.0.0.1:8080;\n        proxy_set_header Host $host;\n    }\n}\n",
  "sites-available/old-landing": "server {\n    listen 80;\n    server_name promo.example.com;\n    root /var/www/promo;\n}\n",
  "conf.d/gzip.conf": "gzip on;\ngzip_types text/css application/javascript application/json;\n",
  "snippets/security-headers.conf": "add_header X-Content-Type-Options nosniff;\nadd_header X-Frame-Options SAMEORIGIN;\n",
};
const enabled = new Set(["shop", "blog", "api"]);

// Managed sites: spec + certificate, rendered like the helper's template (abridged).
const DAY = 86_400_000;
const MARKER = "# tsmonitor-managed v1";
const managed: Record<string, { spec: SiteSpec; cert: CertInfo; rendered: string }> = {};
const noCert = (mode: CertInfo["mode"]): CertInfo => ({ mode, not_after: null, not_before: null, names: [], issuer: null, last_attempt: null, last_error: null });
function render(spec: SiteSpec, cert: CertInfo): string {
  const f = spec.features;
  const tls = spec.ssl.mode !== "none" && cert.not_after !== null;
  const names = spec.domains.join(" ");
  const body = (): string[] => {
    const out: string[] = [];
    if (f.access_log) out.push(`    access_log /var/log/nginx/${spec.name}.access.log;`, `    error_log /var/log/nginx/${spec.name}.error.log;`);
    if (f.client_max_body_mb > 0) out.push(`    client_max_body_size ${f.client_max_body_mb}m;`);
    if (f.gzip) out.push("", "    gzip on;", "    gzip_vary on;", "    gzip_min_length 1024;");
    out.push("");
    if (spec.kind === "proxy") {
      out.push("    location / {", `        proxy_pass ${spec.proxy.upstream};`, "        proxy_http_version 1.1;", `        proxy_set_header Host ${spec.proxy.pass_host ? "$host" : "$proxy_host"};`, "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;");
      if (spec.proxy.websocket) out.push("        proxy_set_header Upgrade $http_upgrade;", "        proxy_set_header Connection \"upgrade\";");
      out.push(`        proxy_read_timeout ${spec.proxy.timeout_secs}s;`, "    }");
    } else {
      out.push(`    root ${spec.static.root};`, `    index ${spec.static.index};`, "", "    location / {", `        try_files $uri $uri/ ${spec.static.spa ? "/index.html" : "=404"};`, "    }");
      if (f.static_cache) out.push("", "    location ~* \\.(?:css|js|png|jpe?g|svg|woff2?)$ {", "        expires 30d;", "    }");
    }
    if (spec.extra.trim()) out.push("", "    # 自定义配置", ...spec.extra.trim().split("\n").map(l => `    ${l}`));
    return out;
  };
  const lines = ["# 由 TServerMonitor 生成。请在面板的 nginx 站点中修改；手动改动会在下次保存时提示覆盖。"];
  if (spec.ssl.mode !== "none" && !tls) lines.push("# 证书尚未就绪：暂时只提供 HTTP，证书就绪后自动启用 HTTPS。");
  lines.push("server {", `    listen ${spec.listen.http};`, `    server_name ${names};`);
  if (spec.ssl.mode === "acme") lines.push("", "    location ^~ /.well-known/acme-challenge/ {", "        alias /etc/nginx/tsmonitor/acme-challenge/;", "    }");
  if (tls && f.force_https) lines.push("", "    location / {", "        return 301 https://$host$request_uri;", "    }");
  else lines.push(...body());
  lines.push("}");
  if (tls) {
    const dir = spec.ssl.mode === "path" ? null : `/etc/nginx/tsmonitor/certs/${spec.name}`;
    lines.push("", "server {", `    listen ${spec.listen.https} ssl;`, ...(f.http2 ? ["    http2 on;"] : []), `    server_name ${names};`, "",
      `    ssl_certificate ${dir ? `${dir}/fullchain.pem` : spec.ssl.cert_path};`, `    ssl_certificate_key ${dir ? `${dir}/privkey.pem` : spec.ssl.key_path};`, "    ssl_protocols TLSv1.2 TLSv1.3;",
      ...(f.hsts ? ["    add_header Strict-Transport-Security \"max-age=31536000\" always;"] : []), ...body(), "}");
  }
  return `${MARKER} name=${spec.name} kind=${spec.kind}\n${lines.join("\n")}\n`;
}
function seedSite(spec: SiteSpec, cert: CertInfo) {
  const rendered = render(spec, cert);
  managed[spec.name] = { spec, cert, rendered };
  files[`sites-available/${spec.name}`] = rendered;
}
const base = (name: string, domains: string[]): SiteSpec => ({
  name, domains, kind: "proxy",
  proxy: { upstream: "http://127.0.0.1:3000", websocket: false, pass_host: true, timeout_secs: 60 },
  static: { root: `/var/www/${name}`, index: "index.html index.htm", spa: false },
  listen: { http: 80, https: 443, ipv6: false },
  features: { force_https: true, http2: true, hsts: false, gzip: true, static_cache: true, access_log: true, client_max_body_mb: 0 },
  ssl: { mode: "none", cert_path: "", key_path: "" },
  extra: "",
});
seedSite(
  { ...base("blog", ["blog.example.com", "www.blog.example.com"]), kind: "static", static: { root: "/var/www/blog", index: "index.html", spa: true }, ssl: { mode: "acme", cert_path: "", key_path: "" } },
  { mode: "acme", not_after: Date.now() + 62 * DAY, not_before: Date.now() - 28 * DAY, names: ["blog.example.com", "www.blog.example.com"], issuer: "C=US, O=Let's Encrypt, CN=R11", last_attempt: Date.now() - 28 * DAY, last_error: null },
);
seedSite(
  { ...base("api", ["api.example.com"]), proxy: { upstream: "http://127.0.0.1:4000", websocket: true, pass_host: true, timeout_secs: 120 }, ssl: { mode: "acme", cert_path: "", key_path: "" } },
  { ...noCert("acme"), last_attempt: Date.now() - 2 * 3_600_000, last_error: "域名验证未通过（Invalid）：api.example.com：urn:ietf:params:acme:error:dns: DNS problem: NXDOMAIN looking up A for api.example.com" },
);
async function sha(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("");
}
const editable = (p: string) => /^(conf\.d|sites-available|snippets)\//.test(p);
const stripComments = (text: string) => text.split("\n").map(l => l.split("#")[0]).join("\n");
const siteTarget = (text: string): string | null => {
  const clean = stripComments(text);
  const proxy = /(?:^|[\s{;])proxy_pass\s+([^;{}]+);/m.exec(clean)?.[1]?.trim().replace(/\s+/g, " ");
  if (proxy) return proxy;
  const root = /(?:^|[\s{;])root\s+([^;{}]+);/m.exec(clean)?.[1]?.trim().replace(/\s+/g, " ");
  const fcgi = /(?:^|[\s{;])fastcgi_pass\s+([^;{}]+);/m.exec(clean)?.[1]?.trim().replace(/\s+/g, " ");
  if (root && fcgi) return `${root} (PHP: ${fcgi})`;
  if (root) return root;
  if (fcgi) return `fastcgi: ${fcgi}`;
  return null;
};
const siteInfo = (text: string) => ({
  server_names: [...new Set([...text.matchAll(/server_name\s+([^;]+);/g)].flatMap(m => m[1].trim().split(/\s+/)))],
  listen: [...text.matchAll(/listen\s+([^;]+);/g)].map(m => m[1].trim()),
});
const sites = (): NginxSites => ({
  layout: "sites_enabled",
  sites: Object.keys(files).filter(p => p.startsWith("sites-available/")).map(p => {
    const name = p.slice("sites-available/".length);
    const info = siteInfo(files[p]);
    const m = managed[name];
    const marked = files[p].startsWith(`${MARKER} name=${name} `);
    const isManaged = Boolean(m && marked);
    const managedTarget = isManaged && m ? (m.spec.kind === "proxy" ? m.spec.proxy.upstream : m.spec.static.root) : null;
    return {
      name, file: p, enabled: enabled.has(name), layout: "sites_enabled" as const, ...info, ssl: info.listen.some(l => l.includes("ssl")),
      managed: isManaged, kind: isManaged ? m.spec.kind : undefined, drifted: Boolean(isManaged && files[p] !== m.rendered),
      cert: isManaged ? m.cert : undefined,
      target: managedTarget || siteTarget(files[p]),
    };
  }),
});

let fw: FirewallStatus = {
  backend: "ufw", active: true, default_incoming: "deny", zone: null, writable: true, ssh_ports: [22],
  rules: [
    { spec: "allow 22/tcp", action: "allow", port: "22", proto: "tcp", from: null, deletable: true },
    { spec: "allow 'Nginx Full'", action: "allow", port: "80,443", proto: "tcp", from: null, deletable: true },
    { spec: "allow from 10.0.0.0/8 to any port 5432 proto tcp", action: "allow", port: "5432", proto: "tcp", from: "10.0.0.0/8", deletable: true },
    { spec: "deny from 192.0.2.66", action: "deny", port: null, proto: null, from: "192.0.2.66", deletable: true },
  ],
  raw: "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\nNginx Full                 ALLOW IN    Anywhere\n5432/tcp                   ALLOW IN    10.0.0.0/8\nAnywhere                   DENY IN     192.0.2.66\n",
  notes: ["Docker 发布的容器端口由 Docker 自己的 iptables 规则放行，不受 ufw/firewalld 入站规则限制"],
};

const sshOptions = [
  ["PermitRootLogin", ["no", "prohibit-password", "yes"]], ["PasswordAuthentication", ["yes", "no"]], ["PubkeyAuthentication", ["yes", "no"]],
  ["KbdInteractiveAuthentication", ["yes", "no"]], ["PermitEmptyPasswords", ["no"]], ["X11Forwarding", ["yes", "no"]],
  ["AllowTcpForwarding", ["yes", "no", "local", "remote"]], ["AllowAgentForwarding", ["yes", "no"]], ["UseDNS", ["yes", "no"]],
  ["MaxAuthTries", []], ["LoginGraceTime", []], ["ClientAliveInterval", []], ["ClientAliveCountMax", []], ["MaxSessions", []], ["Port", []],
] as const;
const ssh: SshConfig = {
  available: true, ports: [22], managed: { MaxAuthTries: "4" }, dropin: "/etc/ssh/sshd_config.d/00-tsmonitor.conf",
  includes_dropins: true, unit: "ssh.service", socket_activated: false,
  effective: {
    port: ["22"], permitrootlogin: ["without-password"], passwordauthentication: ["yes"], pubkeyauthentication: ["yes"],
    kbdinteractiveauthentication: ["no"], permitemptypasswords: ["no"], maxauthtries: ["4"], logingracetime: ["120"],
    clientaliveinterval: ["0"], clientalivecountmax: ["3"], maxsessions: ["10"], x11forwarding: ["yes"],
    allowtcpforwarding: ["yes"], allowagentforwarding: ["yes"], usedns: ["no"],
  },
  options: sshOptions.map(([key, values]) => ({ key, values: [...values] })),
};
const keys: SshKeys = {
  users: ["root", "deploy"],
  keys: [
    { user: "deploy", kind: "ssh-ed25519", fingerprint: "SHA256:q3ZLmIfR8mJ0n1n3oS0r5w1kQ0J6m3n8vXrT2y4aB7c", comment: "deploy@laptop", restricted: false },
    { user: "deploy", kind: "ssh-ed25519", fingerprint: "SHA256:Zx9cV8bN7mL6kJ5hG4fD3sA2pO1iU0yT9rE8wQ7aZ1x", comment: "ci@github-actions", restricted: true },
    { user: "root", kind: "ssh-rsa", fingerprint: "SHA256:Lk4Jh3Gf2Ds1Aq0Wz9Xc8Vb7Nm6Mn5Bv4Cx3Zs2Ad1q", comment: "backup@nas", restricted: false },
  ],
};
const sessions: SshSession[] = [
  { user: "deploy", tty: "pts/0", since: "2026-11-26 09:12", from: "203.0.113.7" },
  { user: "deploy", tty: "pts/1", since: "2026-11-26 10:40", from: "203.0.113.7" },
];

let pending: PendingChange[] = [];
const jobs: OpsJob[] = [];
const audit: AuditEntry[] = [];
let nextJob = 1;

function pushPending(emit: Emit, domain: string, summary: string, revert: () => void) {
  const now = Date.now();
  const p: PendingChange = { id: Math.random().toString(16).slice(2, 14), domain, summary, created_at: now, deadline: now + caps.confirm_secs * 1000, via: "web" };
  pending = [...pending, p];
  reverts.set(p.id, revert);
  emit("ops_pending", pending);
  setTimeout(() => {
    if (pending.some(x => x.id === p.id)) {
      reverts.get(p.id)?.();
      pending = pending.filter(x => x.id !== p.id);
      emit("ops_pending", pending);
    }
  }, caps.confirm_secs * 1000);
  return p;
}
const reverts = new Map<string, () => void>();

type Outcome = { log: string[]; result?: Record<string, unknown>; error?: string };

/** Applies a call to the mock state. Throws ApiError for refusals the daemon would answer directly. */
async function apply(emit: Emit, call: string, a: Record<string, unknown>, dry: boolean): Promise<Outcome> {
  const dryNote = "（演练模式：未实际执行）";
  const str = (k: string) => String(a[k] ?? "");
  switch (call) {
    case "docker.container": {
      const c = inventory.containers.find(x => x.id.startsWith(str("id")) || x.name === str("id"));
      if (!c) return { log: [], error: `找不到容器 ${str("id")}` };
      const action = str("action");
      if (c.protected && action !== "start") return { log: [], error: `${c.name} 受保护（套接字代理、TServerMonitor 本身或配置中列出的容器），不能执行该操作` };
      const log = [`${action} 容器 ${c.name}（${c.id}）`];
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      if (action === "remove") inventory.containers = inventory.containers.filter(x => x !== c);
      else Object.assign(c, action === "start" || action === "restart" ? { state: "running", status: "Up 1 second" } : { state: "exited", status: "Exited (0) 1 second ago" });
      refreshProjects();
      return { log: [...log, "完成"], result: { container: c.name } };
    }
    case "docker.project": {
      const members = inventory.containers.filter(c => c.project === str("name"));
      if (!members.length) return { log: [], error: `找不到 compose 项目 ${str("name")}` };
      const log = members.map(c => `${str("action")} 容器 ${c.name}`);
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      for (const c of members) Object.assign(c, str("action") === "stop" ? { state: "exited", status: "Exited (0) 1 second ago" } : { state: "running", status: "Up 1 second" });
      refreshProjects();
      return { log: [...log, "完成"], result: { containers: members.length } };
    }
    case "docker.image_pull": {
      const ref = str("reference");
      const log = [`拉取镜像 ${ref}`];
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      log.push("latest: Pulling from library", "a2318d6c47ec: Pull complete", "Digest: sha256:4c0fdaa8b6341bfdeca5f18f7837462c80cff90527ee35ef185571e1c327beac", `Status: Downloaded newer image for ${ref}`);
      if (!images.some(i => i.tags.includes(ref))) images = [{ id: Math.random().toString(16).slice(2, 14), tags: [ref], size: 80 * 1024 ** 2, created: Date.now(), containers: 0, dangling: false }, ...images];
      return { log, result: { image: ref } };
    }
    case "docker.image_remove": {
      const img = images.find(i => i.id === str("id") || i.tags.includes(str("id")));
      if (!img) return { log: [], error: "No such image" };
      if (img.containers > 0 && !a.force) return { log: [], error: `conflict: unable to remove ${img.id} - image is being used by a container` };
      if (dry) return { log: [`删除镜像 ${str("id")}`, dryNote], result: { dry_run: true } };
      images = images.filter(i => i !== img);
      return { log: [`删除镜像 ${str("id")}`, `deleted ${img.id}`], result: { removed: 1 } };
    }
    case "docker.image_prune": {
      if (dry) return { log: ["清理未被使用的悬空镜像", dryNote], result: { dry_run: true } };
      const n = images.filter(i => i.dangling).length;
      images = images.filter(i => !i.dangling);
      return { log: ["清理未被使用的悬空镜像", `删除 ${n} 个镜像层，回收 424673280 字节`], result: { deleted: n } };
    }
    case "nginx.test":
      return { log: ["$ nginx -t", "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok", "nginx: configuration file /etc/nginx/nginx.conf test is successful"], result: { ok: true } };
    case "nginx.reload":
      if (dry) return { log: ["（演练模式）将执行 nginx -t，通过后重新加载 nginx"], result: { dry_run: true } };
      return { log: ["$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", "$ systemctl reload nginx.service"], result: { reloaded: true } };
    case "nginx.service": {
      const action = str("action");
      if (!["start", "stop", "restart"].includes(action)) return { log: [], error: `不支持的动作 ${action}` };
      if (nginx.runtime === "none") return { log: [], error: "没有安装 nginx" };
      const cmd = nginx.runtime === "docker" ? `$ docker ${action} ${nginx.container?.name}` : `$ systemctl ${action} nginx.service`;
      const log = action === "stop" ? [cmd] : ["$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", cmd];
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      const running = action !== "stop";
      nginx = {
        ...nginx, running, started_at: running ? Math.floor(Date.now() / 1000) : null, workers: running ? (nginx.runtime === "docker" ? 2 : 4) : null,
        container: nginx.container && { ...nginx.container, state: running ? "running" : "exited" },
      };
      return { log: [...log, running ? "nginx 正在运行" : "nginx 已停止"], result: { running } };
    }
    case "nginx.install": {
      const v = str("version");
      if (nginx.runtime !== "none") return { log: [], error: "nginx 已安装" };
      if (!/^\d+\.\d+\.\d+$/.test(v)) return { log: [], error: `版本号无效：${v}` };
      const log = [
        `$ docker pull nginx:${v}`, `${v}: Pulling from library/nginx`, `Status: Downloaded newer image for nginx:${v}`,
        `$ docker run --rm -v /etc/nginx:/etc/nginx:ro nginx:${v} nginx -t`, "nginx: configuration file /etc/nginx/nginx.conf test is successful",
        `$ docker run -d --name tsmonitor-nginx --network host --restart unless-stopped nginx:${v}`, "探测 http://127.0.0.1/ 通过",
      ];
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      await new Promise(r => setTimeout(r, 1500));
      nginx = nginxDocker(v, null);
      return { log, result: { version: v, image: `nginx:${v}` } };
    }
    case "nginx.upgrade": {
      if (nginx.runtime === "host") {
        const p = nginx.package;
        if (!p?.candidate || p.candidate === p.installed) return { log: [], error: "没有可用的软件包升级" };
        const log = [
          "$ apt-get install --only-upgrade -y nginx", `Unpacking nginx (${p.candidate}) over (${p.installed}) ...`, `Setting up nginx (${p.candidate}) ...`,
          "$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", "nginx 正在运行",
        ];
        if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
        await new Promise(r => setTimeout(r, 1200));
        nginx = { ...nginx, package: { ...p, installed: p.candidate }, started_at: Math.floor(Date.now() / 1000) };
        return { log, result: { installed: p.candidate } };
      }
      if (nginx.runtime !== "docker" || !nginx.container) return { log: [], error: "没有安装 nginx" };
      const v = str("version");
      if (!nginxVersions.versions.some(x => x.version === v)) return { log: [], error: `找不到版本 ${v}` };
      const image = `nginx:${v}`;
      const log = [`$ docker pull ${image}`, `Status: Downloaded newer image for ${image}`, `$ docker run --rm -v /etc/nginx:/etc/nginx:ro ${image} nginx -t`];
      // 1.24 has no http3 directive: demonstrates the automatic revert.
      if (v.startsWith("1.24")) return { log: [...log, "nginx: [emerg] unknown directive \"http3\" in /etc/nginx/sites-enabled/shop:4", "新镜像未通过 nginx -t，保持当前版本"], error: "新镜像未通过 nginx -t：unknown directive \"http3\"；已保持当前版本" };
      log.push("nginx: configuration file /etc/nginx/nginx.conf test is successful", `替换容器 ${nginx.container.name}`, "探测 http://127.0.0.1/ 通过");
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      await new Promise(r => setTimeout(r, 1200));
      nginx = nginxDocker(v, nginx.container.image);
      return { log, result: { version: v, image } };
    }
    case "nginx.rollback": {
      const prev = nginx.previous_image;
      if (nginx.runtime !== "docker" || !prev) return { log: [], error: "没有可回退的版本" };
      const log = [`$ docker run --rm -v /etc/nginx:/etc/nginx:ro ${prev} nginx -t`, "nginx: configuration file /etc/nginx/nginx.conf test is successful", `替换容器 ${nginx.container?.name}`, "探测 http://127.0.0.1/ 通过"];
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      nginx = nginxDocker(prev.replace(/^nginx:/, ""), null);
      return { log, result: { image: prev } };
    }
    case "nginx.site": {
      const name = str("name");
      const on = a.enabled === true;
      const log = [`${on ? "启用" : "停用"}站点 ${name}`];
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      if (on) enabled.add(name); else enabled.delete(name);
      return { log: [...log, "$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", "$ systemctl reload nginx.service"], result: { changed: true } };
    }
    case "nginx.write": {
      const path = str("path");
      const content = str("content");
      if (!editable(path)) return { log: [], error: "只能编辑这些目录中的文件：conf.d, sites-available, snippets" };
      if (/^\s*load_module\b/m.test(content)) return { log: [], error: "拒绝写入：指令 load_module 可在 root 权限下执行代码或改变进程身份，只能在服务器上手动修改" };
      const old = files[path];
      const base = a.base_sha256 ? String(a.base_sha256) : null;
      if ((old === undefined) !== (base === null) || (old !== undefined && (await sha(old)) !== base)) return { log: [], error: `${path} 在你读取之后被修改过，请重新加载后再保存` };
      const diff = unifiedDiff(path, old ?? "", content);
      if (dry) return { log: [`（演练模式）将写入 ${path}，未实际执行`], result: { dry_run: true, diff } };
      if (content.includes("BROKEN")) return { log: [`写入 ${path}`, "$ nginx -t", "nginx: [emerg] unknown directive \"BROKEN\" in /etc/nginx/" + path + ":1", "回滚：nginx -t 未通过"], error: "nginx -t 未通过：\nnginx: [emerg] unknown directive \"BROKEN\"；已恢复原配置" };
      files[path] = content;
      return { log: [`写入 ${path}`, "$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", "$ systemctl reload nginx.service"], result: { changed: true, diff, sha256: await sha(content) } };
    }
    case "nginx.site_save": {
      const spec = structuredClone(a.spec as SiteSpec);
      const path = `sites-available/${spec.name}`;
      const old = files[path];
      const prev = managed[spec.name];
      const base = a.base_sha256 ? String(a.base_sha256) : null;
      if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(spec.name)) return { log: [], error: `无效的站点名：${JSON.stringify(spec.name)}` };
      if (spec.domains.length === 0) return { log: [], error: "至少需要绑定一个域名" };
      if (spec.kind === "proxy" && !/^https?:\/\/[^\s;{}]+$/.test(spec.proxy.upstream)) return { log: [], error: "目标地址必须是 http:// 或 https:// 开头的完整地址" };
      if (spec.kind === "static" && !spec.static.root.startsWith("/var/www/")) return { log: [], error: "网站根目录必须位于这些目录之下：/var/www（helper.toml 的 [nginx] site_roots）" };
      if (spec.ssl.mode === "acme" && spec.listen.http !== 80) return { log: [], error: "自动申请证书使用 HTTP-01 验证，站点必须监听 80 端口" };
      for (const [n, other] of Object.entries(managed)) {
        const hit = n !== spec.name && spec.domains.find(d => other.spec.domains.includes(d));
        if (hit) return { log: [], error: `域名 ${hit} 已绑定在站点 ${n}（sites-available/${n}）上` };
      }
      if (old !== undefined && base === null) return { log: [], error: `已存在同名站点 ${path}，请换一个站点名` };
      if (old !== undefined && base !== null && (await sha(old)) !== base) return { log: [], error: `${path} 在你打开之后被修改过，请重新打开后再保存` };
      if (old !== undefined && prev && old !== prev.rendered && !a.overwrite) return { log: [], error: `${path} 生成后被手动修改过，保存会覆盖这些修改；请查看差异后确认覆盖` };
      const cert = prev && prev.cert.mode === spec.ssl.mode ? prev.cert : noCert(spec.ssl.mode);
      const text = render(spec, cert);
      const diff = unifiedDiff(path, old ?? "", text);
      const log = [`${old === undefined ? "创建" : "更新"} ${path}`];
      if (spec.ssl.mode !== "none" && cert.not_after === null) log.push("证书尚未就绪：先以 HTTP 提供服务，证书就绪后自动切换到 HTTPS");
      if (dry) return { log: [`（演练模式）将${old === undefined ? "创建" : "更新"} ${path}，未实际执行`], result: { dry_run: true, diff, file: path } };
      if (spec.kind === "static") log.push(`创建网站目录 ${spec.static.root}`);
      files[path] = text;
      managed[spec.name] = { spec, cert, rendered: text };
      if (old === undefined) { enabled.add(spec.name); log.push(`启用：sites-enabled/${spec.name}`); }
      return { log: [...log, "$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", "$ systemctl reload nginx.service"], result: { changed: true, diff, file: path, sha256: await sha(text) } };
    }
    case "nginx.site_delete": {
      const name = str("name");
      if (!managed[name]) return { log: [], error: `站点 ${name} 不是由面板管理的站点，请在配置文件中手动删除` };
      const log = [`删除站点 ${name}：sites-available/${name}`];
      if (dry) return { log: [...log, dryNote], result: { dry_run: true } };
      delete files[`sites-available/${name}`];
      delete managed[name];
      enabled.delete(name);
      return { log: [...log, "$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", "$ systemctl reload nginx.service"], result: { changed: true } };
    }
    case "nginx.cert_upload": {
      const m = managed[str("name")];
      if (!m) return { log: [], error: "站点不是由面板管理的站点" };
      if (!str("cert_pem").includes("BEGIN CERTIFICATE")) return { log: [], error: "没有找到证书（应以 -----BEGIN CERTIFICATE----- 开头）" };
      if (!/PRIVATE KEY-----\s*$/.test(str("key_pem"))) return { log: [], error: "私钥必须是未加密的 PEM（-----BEGIN PRIVATE KEY----- 或 RSA / EC PRIVATE KEY）" };
      m.spec.ssl.mode = "upload";
      m.cert = { ...noCert("upload"), not_after: Date.now() + 365 * DAY, not_before: Date.now(), names: m.spec.domains, issuer: "C=CN, O=Example CA, CN=Example RSA CA" };
      m.rendered = render(m.spec, m.cert);
      files[`sites-available/${m.spec.name}`] = m.rendered;
      return { log: [`证书：${m.spec.domains.join(", ")}，签发者 Example CA`, `更新 sites-available/${m.spec.name}（启用 HTTPS）`, "$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", "$ systemctl reload nginx.service"], result: { changed: true, not_after: m.cert.not_after } };
    }
    case "nginx.cert_issue": {
      const m = managed[str("name")];
      if (!m || m.spec.ssl.mode !== "acme") return { log: [], error: "请先把站点的 SSL 方式设为“自动申请”并保存" };
      const log = [`为 ${m.spec.domains.join(", ")} 申请证书（https://acme-v02.api.letsencrypt.org/directory）`];
      if (dry) return { log: [...log, "（演练模式）将进行本机自检、向 CA 申请证书并启用 HTTPS，未实际执行"], result: { dry_run: true } };
      if (m.spec.domains.some(d => d.startsWith("api."))) {
        m.cert = { ...m.cert, last_attempt: Date.now(), last_error: `域名验证未通过（Invalid）：${m.spec.domains[0]}：DNS problem: NXDOMAIN` };
        return { log: [...log, "自检通过：nginx 能正确提供验证文件", `发布 ${m.spec.domains[0]} 的验证文件`, `请求 CA 验证 ${m.spec.domains[0]}`], error: m.cert.last_error ?? "" };
      }
      m.cert = { mode: "acme", not_after: Date.now() + 90 * DAY, not_before: Date.now(), names: m.spec.domains, issuer: "C=US, O=Let's Encrypt, CN=R10", last_attempt: Date.now(), last_error: null };
      m.rendered = render(m.spec, m.cert);
      files[`sites-available/${m.spec.name}`] = m.rendered;
      return {
        log: [...log, "自检通过：nginx 能正确提供验证文件", ...m.spec.domains.flatMap(d => [`发布 ${d} 的验证文件`, `请求 CA 验证 ${d}`]), "验证通过，生成私钥并签发证书",
          `证书已签发：${m.spec.domains.join(", ")}`, `更新 sites-available/${m.spec.name}（启用 HTTPS）`, "$ nginx -t", "nginx: configuration file /etc/nginx/nginx.conf test is successful", "$ systemctl reload nginx.service"],
        result: { changed: true, not_after: m.cert.not_after },
      };
    }
    case "firewall.add": {
      const { action, port, proto, from } = a as { action: string; port: string; proto: string; from?: string | null };
      if ((action === "deny" || action === "reject") && !from && proto !== "udp" && fw.ssh_ports.some(p => String(p) === port))
        return { log: [], error: `拒绝：这条规则会对所有来源封锁 SSH 端口 [${fw.ssh_ports.join(", ")}]，可能导致无法登录服务器` };
      if (pending.some(p => p.domain === "firewall")) return { log: [], error: "已有一项待确认的变更，请先确认或撤销它" };
      const spec = from ? `${action} from ${from} to any port ${port}${proto !== "any" ? ` proto ${proto}` : ""}` : `${action} ${port}${proto !== "any" ? `/${proto}` : ""}`;
      if (dry) return { log: [`$ ufw --force ${spec}`, dryNote], result: { dry_run: true } };
      const before = structuredClone(fw);
      fw = { ...fw, rules: [...fw.rules, { spec, action, port, proto: proto === "any" ? null : proto, from: from ?? null, deletable: true }] };
      const p = pushPending(emit, "firewall", `添加规则：${spec}`, () => { fw = before; });
      return { log: [`$ ufw --force ${spec}`, "Rule added", `已生效。请确认 SSH 仍能新建连接，并在 ${caps.confirm_secs} 秒内确认，否则自动回滚`], result: { pending: p } };
    }
    case "firewall.delete": {
      const r = fw.rules.find(x => x.spec === str("spec"));
      if (!r) return { log: [], error: "找不到这条规则（可能已被修改），请刷新后重试" };
      if (r.action === "allow" && r.port?.split(",").includes("22") && !r.from) return { log: [], error: "拒绝：这是放行 SSH 端口 22 的最后一条规则，删除后可能无法登录服务器" };
      if (pending.some(p => p.domain === "firewall")) return { log: [], error: "已有一项待确认的变更，请先确认或撤销它" };
      if (dry) return { log: [`$ ufw --force delete ${r.spec}`, dryNote], result: { dry_run: true } };
      const before = structuredClone(fw);
      fw = { ...fw, rules: fw.rules.filter(x => x !== r) };
      const p = pushPending(emit, "firewall", `删除规则：${r.spec}`, () => { fw = before; });
      return { log: [`$ ufw --force delete ${r.spec}`, "Rule deleted"], result: { pending: p } };
    }
    case "firewall.toggle": {
      const on = a.enabled === true;
      if (dry) return { log: [`$ ufw --force ${on ? "enable" : "disable"}`, dryNote], result: { dry_run: true } };
      const before = fw.active;
      fw = { ...fw, active: on };
      const p = pushPending(emit, "firewall", on ? "启用 ufw" : "停用 ufw", () => { fw = { ...fw, active: before }; });
      return { log: [`$ ufw --force ${on ? "enable" : "disable"}`], result: { pending: p } };
    }
    case "ssh.set": {
      const opts = (a.options ?? {}) as Record<string, string>;
      const lower = Object.fromEntries(Object.entries(opts).map(([k, v]) => [k.toLowerCase(), v]));
      const eff = { ...ssh.effective, ...Object.fromEntries(Object.entries(lower).map(([k, v]) => [k, [v]])) };
      if (eff.passwordauthentication?.[0] === "no" && eff.pubkeyauthentication?.[0] === "no") return { log: [], error: "拒绝：密码与公钥登录都会被关闭，没有任何登录方式" };
      const merged = { ...ssh.managed, ...opts };
      const text = (m: Record<string, string>) => "# Managed by TServerMonitor (tsmonitor helper). Changes here are overwritten from the dashboard.\n" + Object.entries(m).sort().map(([k, v]) => `${k} ${v}\n`).join("");
      if (dry) return { log: [`将写入 ${ssh.dropin}：${Object.entries(opts).map(([k, v]) => `${k}=${v}`).join(", ")}`, dryNote], result: { dry_run: true, diff: unifiedDiff(ssh.dropin ?? "dropin", text(ssh.managed), text(merged)) } };
      if (pending.some(p => p.domain === "ssh")) return { log: [], error: "已有一项待确认的变更，请先确认或撤销它" };
      const before = structuredClone(ssh);
      Object.assign(ssh, { managed: merged, effective: eff });
      const p = pushPending(emit, "ssh", `sshd：${Object.entries(opts).map(([k, v]) => `${k}=${v}`).join(", ")}`, () => Object.assign(ssh, before));
      return { log: ["$ sshd -t", "$ systemctl reload ssh.service", `已生效。请用新会话测试登录，并在 ${caps.confirm_secs} 秒内确认，否则自动回滚`], result: { pending: p } };
    }
    case "ssh.key_add": {
      const line = str("key").trim();
      const m = /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256)\s+([A-Za-z0-9+/=]{20,})(?:\s+(.*))?$/.exec(line);
      if (!m) return { log: [], error: "无法识别的公钥格式" };
      const fp = `SHA256:${(await sha(m[2])).slice(0, 43)}`;
      if (dry) return { log: [`为 ${str("user")} 添加公钥 ${fp}`, dryNote], result: { dry_run: true, fingerprint: fp } };
      keys.keys.push({ user: str("user"), kind: m[1], fingerprint: fp, comment: m[3] ?? "", restricted: false });
      return { log: [`为 ${str("user")} 添加公钥 ${fp}`], result: { changed: true, fingerprint: fp } };
    }
    case "ssh.key_remove": {
      const before = keys.keys.length;
      if (dry) return { log: [`删除 ${str("user")} 的公钥 ${str("fingerprint")}`, dryNote], result: { dry_run: true } };
      keys.keys = keys.keys.filter(k => !(k.user === str("user") && k.fingerprint === str("fingerprint")));
      return before === keys.keys.length ? { log: [], error: "找不到这把公钥" } : { log: [`删除 ${str("user")} 的公钥 ${str("fingerprint")}`], result: { changed: true, removed: 1 } };
    }
    case "pending.confirm":
    case "pending.revert": {
      const p = pending.find(x => x.id === str("id"));
      if (!p) return { log: [], error: "没有这项待确认变更（可能已超时回滚）" };
      if (call === "pending.revert") reverts.get(p.id)?.();
      pending = pending.filter(x => x !== p);
      emit("ops_pending", pending);
      return { log: [`${call === "pending.confirm" ? "已确认" : "已撤销"}：${p.summary}`], result: { id: p.id } };
    }
    default:
      throw new ApiError(400, `不支持的操作 ${call}`);
  }
}

/** Small line diff for previews (good enough for config files). */
function unifiedDiff(path: string, a: string, b: string): string {
  if (a === b) return "";
  const x = a.split("\n");
  const y = b.split("\n");
  const n = x.length;
  const m = y.length;
  const lcs = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) lcs[i][j] = x[i] === y[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
  const out = [`--- a/${path}`, `+++ b/${path}`, `@@ -1,${n} +1,${m} @@`];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && x[i] === y[j]) { out.push(` ${x[i]}`); i++; j++; }
    else if (i < n && (j >= m || lcs[i + 1][j] >= lcs[i][j + 1])) { out.push(`-${x[i]}`); i++; }
    else { out.push(`+${y[j]}`); j++; }
  }
  return out.join("\n") + "\n";
}

function accessHistory(range: AccessRange): AccessStats {
  const span: Record<AccessRange, [number, number]> = { "1h": [60, 1], "6h": [72, 5], "24h": [96, 15], "7d": [168, 60], "30d": [120, 360] };
  const [points, step] = span[range];
  const now = Math.floor(Date.now() / MIN) * MIN;
  const series = Array.from({ length: points }, (_, i) => {
    const t = now - (points - 1 - i) * step * MIN;
    const day = Math.sin((t / 3_600_000 / 24) * Math.PI * 2 - 1.2);
    const requests = Math.round((700 + 500 * day + Math.random() * 120) * step);
    return { ts: t, requests, s4xx: Math.round(requests * 0.03), s5xx: Math.round(requests * (i % 37 === 5 ? 0.05 : 0.004)), p95_ms: Math.round(180 + 140 * Math.max(0, day) + Math.random() * 60) };
  });
  const requests = series.reduce((s, p) => s + p.requests, 0);
  const s4 = series.reduce((s, p) => s + p.s4xx, 0);
  const s5 = series.reduce((s, p) => s + p.s5xx, 0);
  const short = range === "1h" || range === "6h" || range === "24h";
  return {
    window_mins: points * step, requests, requests_per_min: requests / (points * step),
    status: [Math.round((requests - s4 - s5) * 0.94), Math.round((requests - s4 - s5) * 0.06), s4, s5],
    error_rate_5xx: s5 / requests, bytes: requests * 5_400, series,
    top_paths: short ? [
      { path: "GET /api/orders/<n>", requests: Math.round(requests * 0.31), s5xx: Math.round(s5 * 0.6), avg_ms: 182 },
      { path: "GET /static/<*>", requests: Math.round(requests * 0.22), s5xx: 0, avg_ms: 4 },
      { path: "POST /api/login", requests: Math.round(requests * 0.09), s5xx: Math.round(s5 * 0.2), avg_ms: 240 },
    ] : [],
    top_ips: short ? [{ ip: "203.0.113.42", requests: Math.round(requests * 0.12), s4xx: 12, scan: 0 }] : [],
    latency: short ? { p50_ms: 50, p95_ms: 500, p99_ms: 1000, samples: requests } : null,
    slow_paths: short ? [
      { path: "GET /api/reports/export", requests: 48, s5xx: 2, avg_ms: 3_420 },
      { path: "POST /api/checkout", requests: 612, s5xx: 9, avg_ms: 1_180 },
      { path: "GET /api/search", requests: 2_310, s5xx: 0, avg_ms: 640 },
    ] : [],
    top_hosts: short ? [{ key: "shop.example.com", requests: Math.round(requests * 0.8) }, { key: "api.example.com", requests: Math.round(requests * 0.2) }] : [],
    user_agents: short ? [
      { key: "browser", requests: Math.round(requests * 0.72) }, { key: "bot", requests: Math.round(requests * 0.14) },
      { key: "tool", requests: Math.round(requests * 0.09) }, { key: "scanner", requests: Math.round(requests * 0.01) },
    ] : [],
    suspicious: short ? [
      { ip: "192.0.2.66", requests: 412, s4xx: 401, scan: 388 },
      { ip: "198.51.100.23", requests: 96, s4xx: 71, scan: 12 },
    ] : [],
  };
}

/** Mock sign-in state shared with the auth mock (sudo window). */
export const mockAuth = { sudoUntil: 0 };

function needSudo(): void {
  if (mockAuth.sudoUntil <= Date.now()) throw new ApiError(403, "修改服务器前请先确认密码", "sudo_required");
}

export function opsMock(emit: Emit): Pick<Api, "accessHistory" | "opsCapabilities" | "opsJobs" | "opsJob" | "opsAudit" | "opsPending" | "opsRead" | "opsRun" | "sshSessions"> {
  return {
    accessHistory: range => delay(accessHistory(range), 300),
    opsCapabilities: () => delay(caps),
    opsJobs: (domain, limit = 30) => delay(jobs.filter(j => !domain || j.domain === domain).slice(0, limit).map(({ log: _log, ...j }) => j)),
    opsJob: id => {
      const j = jobs.find(x => x.id === id);
      return j ? delay(j) : Promise.reject(new ApiError(404, "job not found"));
    },
    opsAudit: (limit = 100) => delay(audit.slice(0, limit)),
    opsPending: () => delay(pending),
    opsRead: async <T,>(call: string, params: Record<string, string> = {}): Promise<OpsRead<T>> => {
      const ok = (data: unknown) => delay({ source: "helper" as const, data: data as T });
      switch (call) {
        case "docker.containers": return ok(inventory);
        case "docker.images": return ok(images);
        case "docker.volumes": return ok(volumes);
        case "docker.networks": return ok(networks);
        case "nginx.sites": return ok(sites());
        case "nginx.status": return ok(nginx);
        case "nginx.versions": return ok(nginxVersions);
        case "nginx.log_tail": return ok(nginxLog(params.file === "access" ? "access" : "error", Math.min(Number(params.lines) || 100, 1000)));
        case "nginx.files": return ok(Object.keys(files).sort().map((p): NginxFileEntry => ({ path: p, size: files[p].length, editable: editable(p) })));
        case "nginx.file": {
          const text = files[params.path ?? ""];
          if (text === undefined) return Promise.reject(new ApiError(400, `${params.path} 不存在`));
          return ok({ path: params.path, content: text, sha256: await sha(text), editable: editable(params.path) } satisfies NginxFile);
        }
        case "nginx.site_get": {
          const m = managed[params.name ?? ""];
          if (!m) return Promise.reject(new ApiError(400, `站点 ${params.name} 不是由面板管理的站点`));
          const path = `sites-available/${m.spec.name}`;
          const text = files[path];
          return ok({ spec: m.spec, cert: m.cert, file: path, exists: text !== undefined, enabled: enabled.has(m.spec.name), sha256: text === undefined ? null : await sha(text), drifted: text !== m.rendered } satisfies NginxSiteDetail);
        }
        case "firewall.status": return ok(fw);
        case "ssh.config": return ok(ssh);
        case "ssh.keys": return ok(keys);
        default: return Promise.reject(new ApiError(400, `不支持的查询 ${call}`));
      }
    },
    opsRun: (call, args = {}, dryRun = false) => withSudo(async () => {
      needSudo();
      const id = nextJob++;
      const domain = call.split(".")[0];
      const summary = call;
      const started = Date.now();
      const job: OpsJob = { id, domain, call, summary, args, dry_run: dryRun, via: "web", remote: "127.0.0.1", actor: "admin", status: "running", error: null, result: null, log: "", started_at: started, finished_at: null };
      jobs.unshift(job);
      emit("ops_job", { id, status: "running", line: null });
      const out = await apply(emit, call, args, dryRun);
      for (const line of out.log) {
        job.log += `${line}\n`;
        emit("ops_job", { id, status: "running", line });
      }
      Object.assign(job, { status: out.error ? "failed" : "succeeded", error: out.error ?? null, result: out.result ?? null, finished_at: Date.now() });
      audit.unshift({ id, ts: started, via: "web", remote: "127.0.0.1", actor: "admin", call, summary, dry_run: dryRun, outcome: out.error ? "failed" : "succeeded", detail: out.error ?? null, job_id: id });
      emit("ops_job", { id, status: job.status, line: null });
      return delay(job, 400);
    }),
    sshSessions: () => delay(sessions),
  };
}
