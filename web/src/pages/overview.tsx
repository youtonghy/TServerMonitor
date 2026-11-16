import { useMemo } from "react";
import { Badge } from "@/components/arc/badge/badge";
import { Gauge, type GaugeThreshold } from "@/components/arc/gauge/gauge";
import { MetricCard } from "@/components/arc/metric-card/metric-card";
import { Timeline, type TimelineEvent } from "@/components/arc/timeline/timeline";
import { MetricTicker, type TickerMetric } from "@/components/arc-pro/metric-ticker/metric-ticker";
import { RealtimeStream, type StreamPoint } from "@/components/arc-pro/realtime-stream/realtime-stream";
import { api } from "@/api/client";
import { useLiveMetrics, useLiveMode, useStreamEvent } from "@/api/live";
import type { Alert, HostMetrics, MetricPoint, Snapshot } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { Facts, PageHeader, Panel, QueryView, Section, useNow } from "@/components/panel";
import { formatBytes, formatDuration, formatPercent, formatRate, formatRelative, formatShortDateTime, formatTime, percentOf } from "@/lib/format";
import { alertSourceLabel, generatedByLabel, lookup, modeDescription, modeLabel, modeTone, reportKindLabel, severityLabel, severityTone } from "@/lib/labels";
import { Link } from "@/lib/router";
import styles from "./pages.module.css";

const usageThresholds: GaugeThreshold[] = [
  { from: 0, tone: "success", label: "正常" },
  { from: 75, tone: "warning", label: "偏高" },
  { from: 90, tone: "danger", label: "危险" },
];

const healthThresholds: GaugeThreshold[] = [
  { from: 0, tone: "danger", label: "较差" },
  { from: 60, tone: "warning", label: "一般" },
  { from: 80, tone: "success", label: "良好" },
];

const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

/** Typical gap between samples, so the realtime charts scroll at the feed's cadence (1 s in mock mode, 10 s by default). */
function sampleInterval(samples: HostMetrics[]): number {
  if (samples.length < 3) return 10_000;
  const gaps = samples.slice(-12).map((s, i, list) => (i ? s.ts - list[i - 1].ts : 0)).slice(1).sort((a, b) => a - b);
  return Math.max(500, gaps[Math.floor(gaps.length / 2)] ?? 10_000);
}

function streamPoints(samples: HostMetrics[], pick: (m: HostMetrics) => number, alarm: number, tag: string): StreamPoint[] {
  return samples.map(m => {
    const value = pick(m);
    return { t: m.ts, value, anomaly: value >= alarm ? tag : undefined };
  });
}

/** Prepends stored points that are older than the first live sample. */
function withHistory(points: MetricPoint[] | undefined, samples: HostMetrics[], pick: (p: MetricPoint) => number, live: StreamPoint[]): StreamPoint[] {
  if (!points?.length) return live;
  const first = samples[0]?.ts ?? Number.POSITIVE_INFINITY;
  const seed = points.filter(p => p.ts < first).map(p => ({ t: p.ts, value: pick(p) }));
  return seed.length ? [...seed, ...live] : live;
}

function tickerMetrics(samples: HostMetrics[]): TickerMetric[] {
  const latest = samples[samples.length - 1];
  if (!latest) return [];
  const recent = samples.slice(-24);
  const memPct = (m: HostMetrics) => percentOf(m.mem_used, m.mem_total);
  const mbps = (bps: number) => bps / 1_000_000;
  const pct: Intl.NumberFormatOptions = { style: "unit", unit: "percent", maximumFractionDigits: 1 };
  const rate: Intl.NumberFormatOptions = { style: "unit", unit: "megabyte-per-second", maximumFractionDigits: 1 };
  return [
    { id: "cpu", label: "CPU", value: latest.cpu_pct, format: pct, delta: "absolute", positive: "down", history: recent.map(m => m.cpu_pct), caption: `${latest.cpu_cores} 核` },
    { id: "mem", label: "内存", value: memPct(latest), format: pct, delta: "absolute", positive: "down", history: recent.map(memPct), caption: `${formatBytes(latest.mem_used)} / ${formatBytes(latest.mem_total)}` },
    { id: "load", label: "负载", value: latest.load1, format: { maximumFractionDigits: 2 }, delta: "absolute", positive: "down", history: recent.map(m => m.load1), caption: `5 分钟 ${latest.load5.toFixed(2)}，15 分钟 ${latest.load15.toFixed(2)}` },
    { id: "rx", label: "网络入", value: mbps(latest.net_rx_bps), format: rate, history: recent.map(m => mbps(m.net_rx_bps)), caption: "所有网卡合计" },
    { id: "tx", label: "网络出", value: mbps(latest.net_tx_bps), format: rate, history: recent.map(m => mbps(m.net_tx_bps)), caption: "所有网卡合计" },
  ];
}

function alertEvents(alerts: Alert[]): TimelineEvent[] {
  return alerts.slice(0, 8).map(alert => ({
    id: String(alert.id),
    at: alert.last_seen,
    actor: lookup(alertSourceLabel, alert.source),
    title: alert.title,
    meta: `${severityLabel[alert.severity]}${alert.count > 1 ? `，${alert.count} 次` : ""}${alert.status === "resolved" ? "，已恢复" : ""}`,
    detail: (
      <div className={styles.stack}>
        <p className={styles.text}>{alert.summary}</p>
        {alert.suggestion && <p className={styles.textSecondary}>建议：{alert.suggestion}</p>}
      </div>
    ),
    tone: alert.status === "resolved" ? "success" : alert.severity === "critical" ? "danger" : "neutral",
  }));
}

export default function OverviewPage() {
  const now = useNow();
  const snapshot = useQuery(() => api.snapshot(), [], { refreshMs: 30_000 });
  const alerts = useQuery(() => api.alerts("all", 20), []);
  const samples = useLiveMetrics();
  const liveMode = useLiveMode();

  useStreamEvent("alert", alert => {
    alerts.setData(prev => prev && [alert, ...prev.filter(a => a.id !== alert.id)].sort((a, b) => b.last_seen - a.last_seen));
    snapshot.reload();
  });
  useStreamEvent("report", () => snapshot.reload());
  useStreamEvent("agent", event => {
    if (event.step === null) snapshot.reload();
  });

  const host: HostMetrics | null = samples[samples.length - 1] ?? snapshot.data?.host ?? null;
  const interval = sampleInterval(samples);
  // Seed the realtime charts with stored history so they are not empty until enough live samples arrive.
  const history = useQuery(() => api.metrics("1h"), []);
  const cpuPoints = useMemo(
    () => withHistory(history.data?.points, samples, p => p.cpu_pct, streamPoints(samples, m => m.cpu_pct, 90, "高负载")),
    [history.data, samples],
  );
  const memPoints = useMemo(
    () => withHistory(history.data?.points, samples, p => p.mem_pct, streamPoints(samples, m => percentOf(m.mem_used, m.mem_total), 92, "内存紧张")),
    [history.data, samples],
  );
  const ticker = useMemo(() => tickerMetrics(samples.length ? samples : host ? [host] : []), [samples, host]);
  const mode = liveMode ?? snapshot.data?.mode ?? null;

  return (
    <>
      <PageHeader
        title="总览"
        description={host ? `${host.hostname} · ${host.os} · 内核 ${host.kernel} · 已运行 ${formatDuration(host.uptime_secs)}` : "等待第一次采样"}
      >
        {mode && (
          <div className={styles.row}>
            <Badge tone={modeTone[mode.mode]} dot>{modeLabel[mode.mode]}模式</Badge>
            <span className={`${styles.muted} ${styles.small}`} title={modeDescription[mode.mode]}>
              {mode.reason || modeDescription[mode.mode]}，{formatRelative(mode.since, now)}开始
            </span>
          </div>
        )}
      </PageHeader>

      <section aria-label="实时指标" aria-busy={ticker.length === 0}>
        {ticker.length > 0
          ? <MetricTicker metrics={ticker} label="实时主机指标" locale="zh-CN" overflow="scroll" />
          : <Panel title="实时指标"><QueryView query={snapshot} skeletonLines={1}>{() => <p className={styles.textSecondary}>等待第一次采样</p>}</QueryView></Panel>}
      </section>

      <div className={styles.split}>
        <div className={styles.stack}>
          <Panel title="CPU 使用率" description="实时数据流，悬停可暂停查看">
            <RealtimeStream
              points={cpuPoints}
              label="CPU 使用率"
              unit="%"
              interval={interval}
              windowMs={interval * 60}
              height={180}
              min={0}
              max={100}
              formatValue={v => v.toFixed(1)}
              formatTime={t => formatTime(t)}
              emptyLabel="等待实时数据"
            />
          </Panel>
          <Panel title="内存使用率" description={host ? `${formatBytes(host.mem_used)} / ${formatBytes(host.mem_total)}` : undefined}>
            <RealtimeStream
              points={memPoints}
              label="内存使用率"
              unit="%"
              interval={interval}
              windowMs={interval * 60}
              height={180}
              min={0}
              max={100}
              formatValue={v => v.toFixed(1)}
              formatTime={t => formatTime(t)}
              emptyLabel="等待实时数据"
            />
          </Panel>
        </div>

        <div className={styles.stack}>
          <Section title="健康评分" query={snapshot} skeletonLines={5} minHeight={220}>
            {data => <HealthCard snapshot={data} />}
          </Section>
          <Section title="AI 顾问" query={snapshot} skeletonLines={4}>
            {data => <AiCard snapshot={data} />}
          </Section>
        </div>
      </div>

      <Panel title="磁盘与交换分区" description={host ? `读 ${formatRate(host.disk_read_bps)}，写 ${formatRate(host.disk_write_bps)}` : undefined}>
        {host ? (
          <div className={styles.gauges}>
            {host.disks.map(disk => (
              <Gauge
                key={disk.mount}
                label={disk.mount}
                value={Math.round(percentOf(disk.used, disk.total) * 10) / 10}
                detail={`${formatBytes(disk.used)} / ${formatBytes(disk.total)}，${disk.fs}`}
                thresholds={usageThresholds}
              />
            ))}
            <Gauge
              label="交换分区"
              value={Math.round(percentOf(host.swap_used, host.swap_total) * 10) / 10}
              detail={host.swap_total > 0 ? `${formatBytes(host.swap_used)} / ${formatBytes(host.swap_total)}` : "未启用"}
              thresholds={usageThresholds}
            />
          </div>
        ) : (
          <QueryView query={snapshot} skeletonLines={4}>{() => <p className={styles.textSecondary}>等待第一次采样</p>}</QueryView>
        )}
      </Panel>

      <Section title="容器" query={snapshot} skeletonLines={2} actions={<Link to="/containers" className={styles.small}>查看全部容器</Link>}>
        {data => (
          <div className={styles.kpis}>
            <MetricCard label="容器总数" value={data.containers.total} context={`${data.containers.running} 个运行中`} />
            <MetricCard label="运行中" value={data.containers.running} context={`共 ${data.containers.total} 个`} />
            <MetricCard label="不健康" value={data.containers.unhealthy} context="健康检查失败" />
            <MetricCard label="重启循环" value={data.containers.restart_loops} context="短时间内反复重启" />
            <MetricCard label="内存溢出" value={data.containers.oom} context="被 OOM 终止" />
          </div>
        )}
      </Section>

      <div className={styles.grid2}>
        <Section
          title="最近告警"
          query={alerts}
          skeletonLines={6}
          actions={snapshot.data && <OpenAlertCounts counts={snapshot.data.alerts_open} />}
          isEmpty={data => data.length === 0}
          empty={{ title: "暂无告警", description: "主机运行正常时这里保持为空。" }}
        >
          {data => <Timeline events={alertEvents(data)} now={now} label="最近告警" locale="zh-CN" timeZone={timeZone} maxHeight={420} headingLevel={3} />}
        </Section>

        <Section
          title="最新报告"
          query={snapshot}
          skeletonLines={5}
          isEmpty={data => data.latest_report === null}
          empty={{ title: "还没有报告", description: "第一次巡检完成后会在这里显示摘要。", action: <Link to="/reports">前往报告</Link> }}
        >
          {data => {
            const report = data.latest_report!;
            return (
              <div className={styles.stack}>
                <div className={styles.between}>
                  <p className={styles.itemTitle}>{report.title}</p>
                  <div className={styles.row}>
                    <Badge size="sm">{reportKindLabel[report.kind]}</Badge>
                    <Badge size="sm" tone={report.health_score >= 80 ? "success" : report.health_score >= 60 ? "warning" : "danger"}>评分 {report.health_score}</Badge>
                  </div>
                </div>
                <p className={styles.text}>{report.summary}</p>
                <p className={styles.textSecondary}>
                  {formatShortDateTime(report.created_at)} 由{generatedByLabel[report.generated_by]}生成{report.model ? `（${report.model}）` : ""}
                </p>
                <Link to={`/reports/${report.id}`}>查看完整报告</Link>
              </div>
            );
          }}
        </Section>
      </div>
    </>
  );
}

function OpenAlertCounts({ counts }: { counts: Snapshot["alerts_open"] }) {
  return (
    <div className={styles.row} aria-label="未处理告警">
      {(["critical", "warning", "info"] as const).map(level => (
        <Badge key={level} size="sm" tone={counts[level] > 0 ? severityTone[level] : "neutral"}>
          {severityLabel[level]} {counts[level]}
        </Badge>
      ))}
    </div>
  );
}

function HealthCard({ snapshot }: { snapshot: Snapshot }) {
  const { health } = snapshot;
  return (
    <div className={styles.stack}>
      <div className={styles.gauges}>
        <Gauge label="健康评分" value={health.score} detail={`来源：${generatedByLabel[health.source]}`} thresholds={healthThresholds} />
      </div>
      <Facts
        items={[
          { label: "CPU", value: health.dimensions.cpu },
          { label: "内存", value: health.dimensions.memory },
          { label: "磁盘", value: health.dimensions.disk },
          { label: "日志", value: health.dimensions.logs },
          { label: "安全", value: health.dimensions.security },
          { label: "容器", value: health.dimensions.containers },
          { label: "数据库", value: health.dimensions.database },
        ]}
      />
    </div>
  );
}

function AiCard({ snapshot }: { snapshot: Snapshot }) {
  const { ai } = snapshot;
  return (
    <div className={styles.stack}>
      <div className={styles.row}>
        <Badge tone={ai.enabled ? "success" : "neutral"} dot>{ai.enabled ? "已启用" : "已停用"}</Badge>
        {ai.running && <Link to={`/agent/${ai.running}`}><Badge tone="info" size="sm">巡检进行中</Badge></Link>}
      </div>
      {!ai.enabled && <p className={styles.textSecondary}>原因：{ai.reason ?? "未说明"}</p>}
      <Facts
        items={[
          { label: "今日运行", value: `${ai.runs_today} / ${ai.daily_budget} 次` },
          { label: "模型", value: ai.model ?? "-" },
          { label: "接口格式", value: ai.format ?? "-" },
          { label: "预算剩余", value: formatPercent(ai.daily_budget > 0 ? 100 - percentOf(ai.runs_today, ai.daily_budget) : 0, 0) },
        ]}
      />
    </div>
  );
}
