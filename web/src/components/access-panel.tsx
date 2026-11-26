import { useState } from "react";
import { Badge } from "@/components/arc/badge/badge";
import { BarChart, type BarChartDatum } from "@/components/arc/bar-chart/bar-chart";
import { MetricCard } from "@/components/arc/metric-card/metric-card";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { api } from "@/api/client";
import type { AccessRange, AccessStats } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { Section } from "@/components/panel";
import { formatBytes, formatHourMinute, formatNumber, formatPercent, formatShortDateTime } from "@/lib/format";
import styles from "@/pages/pages.module.css";

const WINDOWS = [
  { value: "15", label: "15 分钟" },
  { value: "60", label: "1 小时" },
  { value: "24h", label: "24 小时" },
  { value: "7d", label: "7 天" },
  { value: "30d", label: "30 天" },
];

const UA_LABEL: Record<string, string> = { browser: "浏览器", bot: "爬虫", tool: "脚本工具", scanner: "扫描器", empty: "无 UA", other: "其他" };

/** Requests, status classes, latency, busiest and slowest paths and clients from nginx access logs.
 * The last hour is live (refreshed every 15 s); longer ranges come from the persisted history. */
export function AccessPanel() {
  const [win, setWin] = useState("15");
  const live = win === "15" || win === "60";
  const access = useQuery(
    () => (live ? api.access(Number(win)) : api.accessHistory(win as AccessRange).then(stats => ({ sources: ["history"], stats }))),
    [win],
    { refreshMs: live ? 15_000 : 120_000 },
  );

  return (
    <Section
      title="访问分析"
      description="来自 nginx 访问日志：请求量、状态码、延迟、热门与慢接口、来源地址；最近 1 小时为实时数据，更长区间来自按分钟保存的历史"
      actions={<SegmentedControl label="时间范围" options={WINDOWS} value={win} onValueChange={setWin} />}
      query={access}
      skeletonLines={6}
      isEmpty={d => d.sources.length === 0}
      empty={{ title: "没有访问日志", description: "在 config.toml 的 [[logs]] 中添加 kind = \"nginx_access\" 的日志源后，这里会显示访问分析。" }}
    >
      {d => <AccessView stats={d.stats} long={!live} />}
    </Section>
  );
}

function AccessView({ stats: s, long }: { stats: AccessStats; long: boolean }) {
  const fmt = (ts: number) => (long && s.window_mins > 1440 ? formatShortDateTime(ts) : formatHourMinute(ts));
  const bars: BarChartDatum[] = s.series.map((p, i) => ({
    key: String(p.ts),
    label: fmt(p.ts),
    axisLabel: i % Math.max(1, Math.round(s.series.length / 6)) === 0 ? fmt(p.ts) : undefined,
    value: p.requests,
  }));
  const uaTotal = (s.user_agents ?? []).reduce((n, u) => n + u.requests, 0);
  const [s2, s3, s4, s5] = s.status;
  return (
    <div className={styles.stack}>
      <div className={styles.kpis}>
        <MetricCard label="请求/分钟" value={Math.round(s.requests_per_min)} context={`共 ${formatNumber(s.requests)} 次`} />
        <MetricCard label="5xx 比例" value={Math.round(s.error_rate_5xx * 1000) / 10} suffix="%" context={`${formatPercent(s.error_rate_5xx * 100, 2)} · ${formatNumber(s5)} 次服务端错误`} />
        {s.latency
          ? <MetricCard label="P95 延迟" value={Math.round(s.latency.p95_ms)} suffix=" ms" context={`P50 ≤ ${Math.round(s.latency.p50_ms)} ms · P99 ≤ ${Math.round(s.latency.p99_ms)} ms`} />
          : <MetricCard label="4xx" value={s4} context="客户端错误" />}
        <MetricCard label="流量" value={Math.round(s.bytes / 1_048_576)} suffix=" MB" context={formatBytes(s.bytes / Math.max(1, s.window_mins * 60)) + "/秒"} />
      </div>
      {bars.length > 0 && (
        <BarChart data={bars} label={long ? "请求数" : "每分钟请求数"} period={long ? `最近 ${Math.round(s.window_mins / 60)} 小时` : `最近 ${s.window_mins} 分钟`} unit="次" averageLabel="平均" valueLabel="请求数" categoryLabel="时间" height={180} formatValue={v => formatNumber(v)} />
      )}
      <p className={`${styles.small} ${styles.muted}`}>
        2xx {formatNumber(s2)} · 3xx {formatNumber(s3)} · 4xx {formatNumber(s4)} · 5xx {formatNumber(s5)}
        {uaTotal > 0 && <> · {(s.user_agents ?? []).map(u => `${UA_LABEL[u.key] ?? u.key} ${formatPercent((u.requests / uaTotal) * 100)}`).join(" · ")}</>}
      </p>
      {!s.latency && !long && <p className={`${styles.small} ${styles.muted}`}>访问日志没有记录请求耗时；在 log_format 末尾加上 $request_time 后即可看到延迟分位数和慢接口。</p>}
      {long && s.window_mins > 1440 && <p className={`${styles.small} ${styles.muted}`}>超过 24 小时的区间只显示请求量与状态码汇总。</p>}
      <div className={styles.grid2}>
        <div className={styles.stack}>
          <h3 className={styles.subheading}>热门接口</h3>
          <ul className={styles.list}>
            {s.top_paths.map(p => (
              <li key={p.path}>
                <div className={styles.between}>
                  <code className={styles.code}>{p.path}</code>
                  <span className={styles.row}>
                    {p.s5xx > 0 && <Badge size="sm" tone="danger">5xx {formatNumber(p.s5xx)}</Badge>}
                    <span className={styles.num}>{formatNumber(p.requests)}</span>
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </div>
        <div className={styles.stack}>
          <h3 className={styles.subheading}>来源地址</h3>
          <ul className={styles.list}>
            {s.top_ips.map(ip => (
              <li key={ip.ip}>
                <div className={styles.between}>
                  <code className={styles.code}>{ip.ip}</code>
                  <span className={styles.num}>{formatNumber(ip.requests)}（{formatPercent((ip.requests / Math.max(1, s.requests)) * 100)}）</span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
      {((s.slow_paths?.length ?? 0) > 0 || (s.suspicious?.length ?? 0) > 0) && (
        <div className={styles.grid2}>
          <div className={styles.stack}>
            <h3 className={styles.subheading}>慢接口（平均耗时）</h3>
            {(s.slow_paths ?? []).length === 0
              ? <p className={`${styles.small} ${styles.muted}`}>没有足够的耗时数据。</p>
              : (
                <ul className={styles.list}>
                  {(s.slow_paths ?? []).map(p => (
                    <li key={p.path}>
                      <div className={styles.between}>
                        <code className={styles.code}>{p.path}</code>
                        <span className={styles.row}>
                          <Badge size="sm" tone={(p.avg_ms ?? 0) >= 1000 ? "warning" : "neutral"}>{Math.round(p.avg_ms ?? 0)} ms</Badge>
                          <span className={`${styles.num} ${styles.muted}`}>{formatNumber(p.requests)} 次</span>
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
          </div>
          <div className={styles.stack}>
            <h3 className={styles.subheading}>可疑来源</h3>
            {(s.suspicious ?? []).length === 0
              ? <p className={`${styles.small} ${styles.muted}`}>没有扫描或大量 4xx 的地址。</p>
              : (
                <ul className={styles.list}>
                  {(s.suspicious ?? []).map(ip => (
                    <li key={ip.ip}>
                      <div className={styles.between}>
                        <code className={styles.code}>{ip.ip}</code>
                        <span className={styles.row}>
                          {(ip.scan ?? 0) > 0 && <Badge size="sm" tone="danger">扫描 {formatNumber(ip.scan ?? 0)}</Badge>}
                          <span className={`${styles.num} ${styles.muted}`}>4xx {formatNumber(ip.s4xx ?? 0)} / {formatNumber(ip.requests)}</span>
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            {(s.suspicious ?? []).length > 0 && <p className={`${styles.small} ${styles.muted}`}>可在 <a href="#/firewall">防火墙</a> 页面封禁这些地址。</p>}
          </div>
        </div>
      )}
    </div>
  );
}
