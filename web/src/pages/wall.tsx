import { useEffect, useMemo, useState } from "react";
import { Maximize2, Minimize2 } from "lucide-react";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Gauge, type GaugeThreshold } from "@/components/arc/gauge/gauge";
import { MetricCard } from "@/components/arc/metric-card/metric-card";
import { RealtimeStream, type StreamPoint } from "@/components/arc-pro/realtime-stream/realtime-stream";
import { api } from "@/api/client";
import { useConnection, useLiveMetrics, useStreamEvent } from "@/api/live";
import type { Alert, HostMetrics, MetricPoint, Severity } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { TokenDialog } from "@/components/token-dialog";
import { formatBytes, formatRate, formatRelative, formatTime, percentOf } from "@/lib/format";
import { alertSourceLabel, lookup, modeLabel, modeTone, severityLabel, severityTone } from "@/lib/labels";
import { Link } from "@/lib/router";
import styles from "./wall.module.css";

const usage: GaugeThreshold[] = [
  { from: 0, tone: "success", label: "正常" },
  { from: 75, tone: "warning", label: "偏高" },
  { from: 90, tone: "danger", label: "危险" },
];
const RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

function useClock(): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

/** Live samples, seeded with stored history older than the first live sample. */
function points(history: MetricPoint[] | undefined, samples: HostMetrics[], pickStored: (p: MetricPoint) => number, pick: (m: HostMetrics) => number): StreamPoint[] {
  const live = samples.map(m => ({ t: m.ts, value: pick(m) }));
  const first = samples[0]?.ts ?? Number.POSITIVE_INFINITY;
  const seed = (history ?? []).filter(p => p.ts < first).map(p => ({ t: p.ts, value: pickStored(p) }));
  return [...seed, ...live];
}

/** Full-screen view for a wall display: live host metrics with the current alerts on the side. */
export default function WallPage() {
  const now = useClock();
  const samples = useLiveMetrics();
  const connection = useConnection();
  const snapshot = useQuery(() => api.snapshot(), [], { refreshMs: 30_000 });
  const alerts = useQuery(() => api.alerts("open", 100), [], { refreshMs: 60_000 });
  const [tokenOpen, setTokenOpen] = useState(false);
  const [full, setFull] = useState(() => Boolean(document.fullscreenElement));

  useStreamEvent("alert", alert => {
    alerts.setData(prev => {
      if (!prev) return prev;
      const rest = prev.filter(a => a.id !== alert.id);
      return alert.status === "open" ? [alert, ...rest] : rest;
    });
    snapshot.reload();
  });

  useEffect(() => {
    const onChange = () => setFull(Boolean(document.fullscreenElement));
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  const toggleFull = () => {
    if (document.fullscreenElement) void document.exitFullscreen();
    else void document.documentElement.requestFullscreen().catch(() => undefined);
  };

  const host = samples[samples.length - 1] ?? snapshot.data?.host ?? null;
  const interval = useMemo(() => {
    if (samples.length < 3) return 10_000;
    const gaps = samples.slice(-12).map((s, i, l) => (i ? s.ts - l[i - 1].ts : 0)).slice(1).sort((a, b) => a - b);
    return Math.max(500, gaps[Math.floor(gaps.length / 2)] ?? 10_000);
  }, [samples]);
  const history = useQuery(() => api.metrics("1h"), []);
  const cpu = useMemo(() => points(history.data?.points, samples, p => p.cpu_pct, m => m.cpu_pct), [history.data, samples]);
  const mem = useMemo(() => points(history.data?.points, samples, p => p.mem_pct, m => percentOf(m.mem_used, m.mem_total)), [history.data, samples]);
  const open = useMemo(
    () => [...(alerts.data ?? [])].sort((a, b) => RANK[a.severity] - RANK[b.severity] || b.last_seen - a.last_seen),
    [alerts.data],
  );
  const counts = snapshot.data?.alerts_open;
  const score = snapshot.data?.health.score;
  const tone = score === undefined ? "neutral" : score >= 80 ? "success" : score >= 60 ? "warning" : "danger";

  return (
    <div className={styles.wall}>
      <main className={styles.main}>
        <header className={styles.header}>
          <div>
            <h1 className={styles.host}>{host?.hostname ?? "TServerMonitor"}</h1>
            <p className={styles.sub}>
              {new Date(now).toLocaleString("zh-CN", { hour12: false })}
              {snapshot.data && <> · <Badge tone={modeTone[snapshot.data.mode.mode]} dot>{modeLabel[snapshot.data.mode.mode]}模式</Badge></>}
              {connection !== "open" && <> · <Badge tone="warning" dot>实时数据{connection === "connecting" ? "连接中" : "已断开"}</Badge></>}
            </p>
          </div>
          <div className={styles.score} data-tone={tone} aria-label="健康评分">
            <span className={styles.scoreValue}>{score === undefined ? "--" : Math.round(score)}</span>
            <span className={styles.scoreLabel}>健康评分</span>
          </div>
          <div className={styles.tools}>
            <Button variant="ghost" size="sm" onClick={toggleFull} aria-label={full ? "退出全屏" : "全屏"}>
              {full ? <Minimize2 size={16} strokeWidth={1.75} aria-hidden="true" /> : <Maximize2 size={16} strokeWidth={1.75} aria-hidden="true" />}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setTokenOpen(true)}>令牌</Button>
            <Link to="/">返回</Link>
          </div>
        </header>

        <div className={styles.charts}>
          <section className={styles.card} aria-label="CPU">
            <RealtimeStream points={cpu} label="CPU 使用率" unit="%" interval={interval} windowMs={interval * 60} height={200} min={0} max={100} formatValue={v => v.toFixed(1)} formatTime={t => formatTime(t)} emptyLabel="等待实时数据" />
          </section>
          <section className={styles.card} aria-label="内存">
            {host && <p className={styles.cardTitle}>{formatBytes(host.mem_used)} / {formatBytes(host.mem_total)}</p>}
            <RealtimeStream points={mem} label="内存使用率" unit="%" interval={interval} windowMs={interval * 60} height={200} min={0} max={100} formatValue={v => v.toFixed(1)} formatTime={t => formatTime(t)} emptyLabel="等待实时数据" />
          </section>
        </div>

        <div className={styles.row}>
          <section className={`${styles.card} ${styles.gauges}`} aria-label="磁盘">
            {host?.disks.slice(0, 4).map(d => (
              <Gauge key={d.mount} label={d.mount} value={Math.round(percentOf(d.used, d.total) * 10) / 10} detail={`${formatBytes(d.used)} / ${formatBytes(d.total)}`} thresholds={usage} />
            ))}
          </section>
          <section className={`${styles.card} ${styles.kpis}`} aria-label="概况">
            <MetricCard label="负载" value={host ? Math.round(host.load1 * 100) / 100 : 0} context={host ? `${host.cpu_cores} 核` : "等待采样"} />
            <MetricCard label="网络接收" value={host ? Math.round(host.net_rx_bps / 1024) : 0} suffix=" KB/s" context={host ? formatRate(host.net_tx_bps) + " 发送" : "等待采样"} />
            <MetricCard label="容器运行" value={snapshot.data?.containers.running ?? 0} context={snapshot.data ? `共 ${snapshot.data.containers.total} · 不健康 ${snapshot.data.containers.unhealthy}` : "加载中"} />
          </section>
        </div>
      </main>

      <aside className={styles.rail} aria-label="当前告警">
        <div className={styles.railHeader}>
          <h2 className={styles.railTitle}>当前告警</h2>
          <div className={styles.counts}>
            <Badge tone="danger" dot>严重 {counts?.critical ?? 0}</Badge>
            <Badge tone="warning" dot>警告 {counts?.warning ?? 0}</Badge>
          </div>
        </div>
        {open.length === 0
          ? <p className={styles.calm}>{alerts.status === "loading" ? "加载中…" : "一切正常，没有未处理的告警"}</p>
          : (
            <ul className={styles.alerts}>
              {open.map(a => <AlertItem key={a.id} alert={a} now={now} />)}
            </ul>
          )}
      </aside>
      <TokenDialog open={tokenOpen} onOpenChange={setTokenOpen} />
    </div>
  );
}

function AlertItem({ alert: a, now }: { alert: Alert; now: number }) {
  return (
    <li className={styles.alert} data-severity={a.severity}>
      <div className={styles.alertHead}>
        <Badge size="sm" tone={severityTone[a.severity]}>{severityLabel[a.severity]}</Badge>
        <span className={styles.alertMeta}>{lookup(alertSourceLabel, a.source)} · {formatRelative(a.last_seen, now)}{a.count > 1 ? ` · ${a.count} 次` : ""}</span>
      </div>
      <p className={styles.alertTitle}>{a.title}</p>
      <p className={styles.alertSummary}>{a.summary}</p>
      {a.acked_at && <span className={styles.alertMeta}>已确认</span>}
    </li>
  );
}
