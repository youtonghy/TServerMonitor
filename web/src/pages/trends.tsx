import { useMemo, useState } from "react";
import { BrushChart } from "@/components/arc/brush-chart/brush-chart";
import { LineChart, type LineChartDatum } from "@/components/arc/line-chart/line-chart";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { SmallMultiples } from "@/components/arc-pro/small-multiples/small-multiples";
import { api } from "@/api/client";
import type { MetricPoint, MetricsRange } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { PageHeader, Panel, QueryView } from "@/components/panel";
import { formatAxisTime, formatDateTime, formatNumber, formatShortDateTime } from "@/lib/format";
import styles from "./pages.module.css";

const RANGES: { value: MetricsRange; label: string }[] = [
  { value: "1h", label: "1 小时" },
  { value: "6h", label: "6 小时" },
  { value: "24h", label: "24 小时" },
  { value: "7d", label: "7 天" },
  { value: "30d", label: "30 天" },
];

/** Keeps at most `max` points by striding, so dense ranges stay light for SVG charts. */
function thin<T>(points: T[], max: number): T[] {
  if (points.length <= max) return points;
  const step = points.length / max;
  return Array.from({ length: max }, (_, i) => points[Math.floor(i * step)]);
}

function compareData(points: MetricPoint[]): LineChartDatum[] {
  const list = thin(points, 180);
  const span = list.length > 1 ? list[list.length - 1].ts - list[0].ts : 0;
  const every = Math.max(1, Math.round(list.length / 6));
  return list.map((p, i) => ({
    key: String(p.ts),
    label: formatDateTime(p.ts),
    axisLabel: i % every === 0 ? formatAxisTime(p.ts, span) : undefined,
    values: { cpu: p.cpu_pct, mem: p.mem_pct, swap: p.swap_pct, disk: p.disk_pct },
  }));
}

const MB = 1_000_000;

export default function TrendsPage() {
  const [range, setRange] = useState<MetricsRange>("24h");
  const metrics = useQuery(() => api.metrics(range), [range], { refreshMs: 60_000 });
  const rangeLabel = RANGES.find(r => r.value === range)?.label ?? range;

  const io = useMemo(() => {
    const points = thin(metrics.data?.points ?? [], 120);
    return {
      periods: points.map(p => ({ short: formatShortDateTime(p.ts), long: formatDateTime(p.ts) })),
      series: [
        { id: "disk_read", name: "磁盘读 MB/s", values: points.map(p => p.disk_read_bps / MB) },
        { id: "disk_write", name: "磁盘写 MB/s", values: points.map(p => p.disk_write_bps / MB) },
        { id: "net_rx", name: "网络入 MB/s", values: points.map(p => p.net_rx_bps / MB) },
        { id: "net_tx", name: "网络出 MB/s", values: points.map(p => p.net_tx_bps / MB) },
        { id: "load1", name: "1 分钟负载", values: points.map(p => p.load1) },
      ],
      lag: Math.max(1, Math.round(points.length / 4)),
    };
  }, [metrics.data]);

  const empty = { title: "该时间段没有数据", description: "守护进程启动后会持续记录指标，稍后再查看或换一个时间范围。" };
  const isEmpty = (data: { points: MetricPoint[] }) => data.points.length === 0;

  return (
    <>
      <PageHeader title="趋势" description={`最近 ${rangeLabel}的主机指标历史`}>
        <SegmentedControl label="时间范围" options={RANGES} value={range} onValueChange={value => setRange(value as MetricsRange)} />
      </PageHeader>

      <Panel title="CPU 使用率" description="拖动下方概览选择区间，可放大查看细节" busy={metrics.status === "loading"}>
        <QueryView query={metrics} skeletonLines={10} isEmpty={isEmpty} empty={empty} minHeight={320}>
          {data => (
            <BrushChart
              key={range}
              data={data.points.map(p => ({ date: p.ts, value: p.cpu_pct }))}
              label="CPU 使用率"
              unit="%"
              height={240}
              formatValue={v => `${v.toFixed(1)}`}
              formatTick={v => `${Math.round(v)}`}
              formatDate={d => formatDateTime(d.getTime())}
              emptyLabel="该时间段没有数据"
            />
          )}
        </QueryView>
      </Panel>

      <Panel title="资源使用率对比" description="CPU、内存、交换分区与磁盘的百分比" busy={metrics.status === "loading"}>
        <QueryView query={metrics} skeletonLines={8} isEmpty={isEmpty} empty={empty} minHeight={260}>
          {data => (
            <LineChart
              data={compareData(data.points)}
              series={[
                { key: "cpu", label: "CPU", color: "var(--series-1)" },
                { key: "mem", label: "内存", color: "var(--series-2)" },
                { key: "swap", label: "交换分区", color: "var(--series-3)", dashed: true },
                { key: "disk", label: "磁盘", color: "var(--series-4)" },
              ]}
              label="资源使用率对比"
              unit="%"
              height={260}
              categoryLabel="时间"
              emptyLabel="该时间段没有数据"
              loading={metrics.refreshing}
              formatValue={v => `${v.toFixed(1)}%`}
              formatTick={v => `${Math.round(v)}`}
            />
          )}
        </QueryView>
      </Panel>

      {metrics.status === "ready" && !isEmpty(metrics.data) ? (
        <SmallMultiples
          key={range}
          title="磁盘 IO、网络与负载"
          description={`最近 ${rangeLabel}，磁盘与网络单位为 MB/s，负载为 1 分钟平均值`}
          series={io.series}
          periods={io.periods}
          growthLag={io.lag}
          defaultScale="independent"
          defaultSort="name"
          formatValue={v => formatNumber(v)}
          formatTick={v => formatNumber(v)}
        />
      ) : (
        <Panel title="磁盘 IO、网络与负载" busy={metrics.status === "loading"}>
          <QueryView query={metrics} skeletonLines={8} isEmpty={isEmpty} empty={empty} minHeight={260}>
            {() => <p className={styles.textSecondary}>正在准备图表</p>}
          </QueryView>
        </Panel>
      )}
    </>
  );
}
