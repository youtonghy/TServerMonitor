// Managed nginx sites: form defaults (mirroring the helper's) and certificate status labels.
import type { BadgeTone } from "@/components/arc/badge/badge";
import type { CertInfo, SiteKind, SiteSpec, SslMode } from "@/api/types";

export function defaultSpec(): SiteSpec {
  return {
    name: "",
    domains: [],
    kind: "proxy",
    proxy: { upstream: "", websocket: false, pass_host: true, timeout_secs: 60 },
    static: { root: "", index: "index.html index.htm", spa: false },
    listen: { http: 80, https: 443, ipv6: false },
    features: { force_https: true, http2: true, hsts: false, gzip: true, static_cache: true, access_log: true, client_max_body_mb: 0 },
    ssl: { mode: "none", cert_path: "", key_path: "" },
    extra: "",
  };
}

export const siteKindLabel: Record<SiteKind, string> = { proxy: "反向代理", static: "静态站点" };
export const sslModeLabel: Record<SslMode, string> = { none: "不启用", acme: "自动申请", upload: "上传证书", path: "服务器上的证书" };

export const SITE_NAME = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;

/** Splits the domain text box: one per line, or separated by spaces or commas. */
export function parseDomains(text: string): string[] {
  const out: string[] = [];
  for (const d of text.split(/[\s,，]+/)) {
    const v = d.trim().toLowerCase().replace(/\.$/, "");
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

/** Suggested site name from the first domain: `www.shop.example.com` -> `shop.example.com`. */
export function nameFromDomain(domain: string): string {
  return domain.replace(/^\*\./, "").replace(/^www\./, "").replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 64);
}

const DAY = 86_400_000;

export function certStatus(c: CertInfo | undefined, now: number): { label: string; tone: BadgeTone; detail?: string } {
  if (!c || c.mode === "none") return { label: "未启用", tone: "neutral" };
  if (c.not_after === null) {
    return c.last_error
      ? { label: "申请失败", tone: "danger", detail: c.last_error }
      : { label: c.mode === "acme" ? "待申请" : "未安装", tone: "warning" };
  }
  const days = Math.floor((c.not_after - now) / DAY);
  const date = new Date(c.not_after).toLocaleDateString("zh-CN");
  if (days < 0) return { label: "已过期", tone: "danger", detail: `过期于 ${date}` };
  if (days < 14) return { label: `${days} 天后到期`, tone: "warning", detail: c.last_error ?? `到期 ${date}` };
  return { label: `有效至 ${date}`, tone: c.last_error ? "warning" : "success", detail: c.last_error ?? undefined };
}

/** True when the certificate name `pattern` (possibly `*.example.com`) covers `host`. */
export function covers(pattern: string, host: string): boolean {
  if (!pattern.startsWith("*.")) return pattern === host;
  const dot = host.indexOf(".");
  return dot > 0 && host.slice(dot + 1) === pattern.slice(2);
}

export function formatSiteDomains(names: string[]): string {
  if (names.length === 0) return "—";
  if (names.length === 1 && names[0] === "_") return "默认站点 (_)";
  return names.join(" ");
}

export function formatListen(listen: string[]): string {
  if (listen.length === 0) return "—";
  return [...new Set(listen)].join(" · ");
}

/**
 * One-line listen summary for tables: IPv4/IPv6 duplicates of the same port merge and
 * `default_server` becomes a trailing "默认" marker. The full list stays in formatListen.
 */
export function formatListenCompact(listen: string[]): string {
  if (listen.length === 0) return "—";
  let isDefault = false;
  const parts: string[] = [];
  for (const raw of listen) {
    const words = raw.trim().split(/\s+/);
    if (words.includes("default_server")) isDefault = true;
    const addr = (words[0] ?? "").replace(/^\[::\]:/, "").replace(/^0\.0\.0\.0:/, "");
    const flags = words.slice(1).filter(w => w === "ssl" || w === "quic");
    const label = [addr, ...flags].join(" ");
    if (label && !parts.includes(label)) parts.push(label);
  }
  return parts.join(" · ") + (isDefault ? " · 默认" : "");
}
