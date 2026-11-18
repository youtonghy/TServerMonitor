import { useState } from "react";
import { Badge } from "@/components/arc/badge/badge";
import { BarChart, type BarChartDatum } from "@/components/arc/bar-chart/bar-chart";
import { MetricCard } from "@/components/arc/metric-card/metric-card";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { api } from "@/api/client";
import type { AccessStats } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { Section } from "@/components/panel";
import { formatBytes, formatHourMinute, formatNumber, formatPercent } from "@/lib/format";
import styles from "@/pages/pages.module.css";

const WINDOWS = [
  { value: "15", label: "15 分钟" },
  { value: "60", label: "1 小时" },
];

/** Requests, status classes, busiest paths and clients from nginx access logs, refreshed every 15 s. */
export function AccessPanel() {
  const [win, setWin] = useState("15");
  const access = useQuery(() => api.access(Number(win)), [win], { refreshMs: 15_000 });

  return (
    <Section
      title="实时访问"
      description="来自 nginx 访问日志：请求量、状态码与热门接口、来源地址（内存中保留最近 1 小时）"
      actions={<SegmentedControl label="时间范围" options={WINDOWS} value={win} onValueChange={setWin} />}
      query={access}
      skeletonLines={6}
      isEmpty={d => d.sources.length === 0}
      empty={{ title: "没有访问日志", description: "在 config.toml 的 [[logs]] 中添加 kind = \"nginx_access\" 的日志源后，这里会显示实时访问分析。" }}
    >
      {d => <AccessView stats={d.stats} />}
    </Section>
  );
}

function AccessView({ stats: s }: { stats: AccessStats }) {
  const bars: BarChartDatum[] = s.series.map((p, i) => ({
    key: String(p.ts),
    label: formatHourMinute(p.ts),
    axisLabel: i % Math.max(1, Math.round(s.series.length / 6)) === 0 ? formatHourMinute(p.ts) : undefined,
    value: p.requests,
  }));
  const [s2, s3, s4, s5] = s.status;
  return (
    <div className={styles.stack}>
      <div className={styles.kpis}>
        <MetricCard label="请求/分钟" value={Math.round(s.requests_per_min)} context={`共 ${formatNumber(s.requests)} 次`} />
        <MetricCard label="5xx 比例" value={Math.round(s.error_rate_5xx * 1000) / 10} suffix="%" context={`${formatPercent(s.error_rate_5xx * 100, 2)} · ${formatNumber(s5)} 次服务端错误`} />
        <MetricCard label="4xx" value={s4} context="客户端错误" />
        <MetricCard label="流量" value={Math.round(s.bytes / 1_048_576)} suffix=" MB" context={formatBytes(s.bytes / Math.max(1, s.window_mins * 60)) + "/秒"} />
      </div>
      {bars.length > 0 && (
        <BarChart data={bars} label="每分钟请求数" period={`最近 ${s.window_mins} 分钟`} unit="次" averageLabel="平均" valueLabel="请求数" categoryLabel="时间" height={180} formatValue={v => formatNumber(v)} />
      )}
      <p className={`${styles.small} ${styles.muted}`}>
        2xx {formatNumber(s2)} · 3xx {formatNumber(s3)} · 4xx {formatNumber(s4)} · 5xx {formatNumber(s5)}
      </p>
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
    </div>
  );
}
