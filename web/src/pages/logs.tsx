import { useMemo, useState } from "react";
import { ActivityHeatmap } from "@/components/arc/activity-heatmap/activity-heatmap";
import { Badge } from "@/components/arc/badge/badge";
import { BarChart, type BarChartDatum } from "@/components/arc/bar-chart/bar-chart";
import { Select } from "@/components/arc/select/select";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { Streamgraph, type StreamgraphDatum } from "@/components/arc/streamgraph/streamgraph";
import { api } from "@/api/client";
import { AccessPanel } from "@/components/access-panel";
import type { LogCluster, LogRatesResponse, LogSource } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { PageHeader, Section, useNow } from "@/components/panel";
import { formatCompact, formatDateTime, formatHourMinute, formatNumber, formatRelative } from "@/lib/format";
import { logKindLabel, logLevelLabel, logLevelTone, lookup, lookupTone } from "@/lib/labels";
import styles from "./pages.module.css";

type SourceRow = {
  name: string; kind: string; location: string; rate_per_min: number; errors_per_min: number; lines_total: number; errors_total: number;
};
type ClusterRow = {
  fingerprint: string; level: string; source: string; template: string; sample: string; count: number; last_seen: number; first_seen: number;
};

const ALL = "all";
const LEVELS = ["error", "warning", "info", "slow"];

function streamData(rates: LogRatesResponse): StreamgraphDatum[] {
  const first = rates.series[0]?.points ?? [];
  const every = Math.max(1, Math.round(first.length / 6));
  return first.map((point, i) => ({
    key: String(point.ts),
    label: formatDateTime(point.ts),
    axisLabel: i % every === 0 ? formatHourMinute(point.ts) : undefined,
    values: Object.fromEntries(rates.series.map(s => [s.source, s.points[i]?.lines])),
  }));
}

/** Errors summed across sources, bucketed by hour for the last 24 hours. */
function hourlyErrors(rates: LogRatesResponse): BarChartDatum[] {
  const buckets = new Map<number, number>();
  for (const series of rates.series) {
    for (const point of series.points) {
      const hour = Math.floor(point.ts / 3_600_000) * 3_600_000;
      buckets.set(hour, (buckets.get(hour) ?? 0) + point.errors);
    }
  }
  const hours = [...buckets.keys()].sort((a, b) => a - b).slice(-24);
  return hours.map((hour, i) => ({
    key: String(hour),
    label: `${formatHourMinute(hour)} 起一小时`,
    axisLabel: i % 4 === 0 ? formatHourMinute(hour) : undefined,
    value: buckets.get(hour) ?? 0,
  }));
}

export default function LogsPage() {
  const now = useNow();
  const rates = useQuery(() => api.logRates("24h"), [], { refreshMs: 60_000 });
  const sources = useQuery(() => api.logSources(), [], { refreshMs: 60_000 });
  const daily = useQuery(() => api.dailyErrors(365), []);
  const [source, setSource] = useState(ALL);
  const [level, setLevel] = useState(ALL);
  const clusters = useQuery(
    () => api.logClusters({ source: source === ALL ? undefined : source, level: level === ALL ? undefined : level, limit: 100 }),
    [source, level],
  );

  const sourceOptions = useMemo(
    () => [{ value: ALL, label: "全部来源" }, ...(sources.data ?? []).map(s => ({ value: s.name, label: s.name }))],
    [sources.data],
  );

  const sourceColumns: DataColumn<SourceRow>[] = [
    { key: "name", label: "来源", sortable: true, render: (_v, row) => <span className={styles.strong}>{row.name}</span> },
    { key: "kind", label: "类型", sortable: true, render: (_v, row) => lookup(logKindLabel, row.kind) },
    { key: "location", label: "路径或容器", render: (_v, row) => <code className={styles.code}>{row.location}</code> },
    { key: "rate_per_min", label: "行/分钟", numeric: true, sortable: true, render: (_v, row) => formatNumber(row.rate_per_min) },
    { key: "errors_per_min", label: "错误/分钟", numeric: true, sortable: true, render: (_v, row) => formatNumber(row.errors_per_min) },
    { key: "lines_total", label: "总行数", numeric: true, sortable: true, render: (_v, row) => formatCompact(row.lines_total) },
    { key: "errors_total", label: "总错误数", numeric: true, sortable: true, render: (_v, row) => formatCompact(row.errors_total) },
  ];

  const clusterColumns: DataColumn<ClusterRow>[] = [
    { key: "level", label: "级别", sortable: true, render: (_v, row) => <Badge tone={lookupTone(logLevelTone, row.level)} size="sm">{lookup(logLevelLabel, row.level)}</Badge> },
    { key: "source", label: "来源", sortable: true },
    {
      key: "template", label: "模板", width: "50%",
      render: (_v, row) => <span className={styles.template} title={row.sample}><code className={styles.code}>{row.template}</code></span>,
    },
    { key: "count", label: "次数", numeric: true, sortable: true, render: (_v, row) => formatNumber(row.count) },
    { key: "last_seen", label: "最近出现", numeric: true, sortable: true, render: (_v, row) => <time dateTime={new Date(row.last_seen).toISOString()} title={formatDateTime(row.last_seen)}>{formatRelative(row.last_seen, now)}</time> },
  ];

  return (
    <>
      <PageHeader title="日志" description="实时访问、各日志来源的速率、错误分布与聚类模板" />

      <AccessPanel />

      <Section
        title="各来源日志量"
        description="最近 24 小时，每 10 分钟的行数"
        query={rates}
        skeletonLines={8}
        isEmpty={data => data.series.length === 0}
        empty={{ title: "暂无日志速率", description: "配置日志来源后，这里会显示每个来源的日志量。" }}
      >
        {data => (
          <Streamgraph
            data={streamData(data)}
            series={data.series.map(s => ({ key: s.source, label: s.source }))}
            label="各来源日志量"
            unit="行"
            height={280}
            categoryLabel="时间"
            emptyLabel="该时间段没有数据"
            formatValue={value => formatNumber(value)}
          />
        )}
      </Section>

      <div className={styles.grid2}>
        <Section
          title="每小时错误数"
          description="所有来源合计"
          query={rates}
          skeletonLines={5}
          isEmpty={data => data.series.length === 0}
          empty={{ title: "暂无错误统计", description: "日志来源产生数据后会显示每小时的错误数。" }}
        >
          {data => (
            <BarChart
              data={hourlyErrors(data)}
              label="每小时错误数"
              period="最近 24 小时"
              unit="条"
              averageLabel="小时平均"
              valueLabel="错误数"
              categoryLabel="时段"
              height={200}
              formatValue={value => formatNumber(value)}
            />
          )}
        </Section>

        <Section
          title="每日错误"
          description="最近一年每天的错误条数"
          query={daily}
          skeletonLines={5}
          isEmpty={data => data.length === 0}
          empty={{ title: "暂无历史错误", description: "守护进程运行满一天后会开始记录每日错误数。" }}
        >
          {data => (
            <div className={styles.scrollX}>
              <ActivityHeatmap
                days={data}
                label="每日错误"
                period="最近 365 天"
                unit={{ one: "条错误", other: "条错误" }}
                weekStartsOn={1}
                locale="zh-CN"
              />
            </div>
          )}
        </Section>
      </div>

      <Section
        title="日志来源"
        query={sources}
        flush
        skeletonLines={6}
        isEmpty={data => data.length === 0}
        empty={{ title: "没有日志来源", description: "在配置文件中添加日志路径或容器后，这里会列出它们。" }}
      >
        {data => (
          <SortableDataTable<SourceRow>
            rows={data.map(toSourceRow)}
            rowKey="name"
            caption="日志来源"
            columns={sourceColumns}
            defaultSort={{ key: "errors_per_min", direction: "desc" }}
            emptyMessage="没有日志来源"
            itemName={{ one: "个来源", other: "个来源" }}
          />
        )}
      </Section>

      <Section
        title="日志聚类"
        description="相同模板的日志合并为一类，按最近出现时间排序"
        query={clusters}
        flush
        skeletonLines={8}
        actions={
          <div className={styles.filters}>
            <Select label="来源" options={sourceOptions} value={source} onValueChange={setSource} />
            <Select
              label="级别"
              options={[{ value: ALL, label: "全部级别" }, ...LEVELS.map(l => ({ value: l, label: lookup(logLevelLabel, l) }))]}
              value={level}
              onValueChange={setLevel}
            />
          </div>
        }
        isEmpty={data => data.length === 0}
        empty={{ title: "没有匹配的聚类", description: "换一个来源或级别再试。" }}
      >
        {data => (
          <SortableDataTable<ClusterRow>
            rows={data.map(toClusterRow)}
            rowKey="fingerprint"
            caption="日志聚类"
            columns={clusterColumns}
            defaultSort={{ key: "last_seen", direction: "desc" }}
            emptyMessage="没有匹配的聚类"
            itemName={{ one: "个聚类", other: "个聚类" }}
          />
        )}
      </Section>
    </>
  );
}

function toSourceRow(s: LogSource): SourceRow {
  return {
    name: s.name, kind: s.kind, location: s.path ?? (s.container ? `容器 ${s.container}` : "-"),
    rate_per_min: s.rate_per_min, errors_per_min: s.errors_per_min, lines_total: s.lines_total, errors_total: s.errors_total,
  };
}

function toClusterRow(c: LogCluster): ClusterRow {
  return { ...c };
}
