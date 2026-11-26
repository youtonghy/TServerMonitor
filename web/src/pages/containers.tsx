import { useMemo, useState, type ReactNode } from "react";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { DockerManage } from "@/components/docker-manage";
import { Badge } from "@/components/arc/badge/badge";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { Drawer, DrawerContent, useDrawerItem } from "@/components/arc/drawer/drawer";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { Sparkline } from "@/components/arc/sparkline/sparkline";
import { Treemap } from "@/components/arc/treemap/treemap";
import { HorizonChart } from "@/components/arc-pro/horizon-chart/horizon-chart";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { ContainerInfo } from "@/api/types";
import { useQuery, type Query } from "@/api/useQuery";
import { Facts, PageHeader, Panel, QueryView, Section, useNow } from "@/components/panel";
import { formatBytes, formatDateTime, formatPercent, formatRelative, formatTime, percentOf } from "@/lib/format";
import { containerStateLabel, containerStateTone, healthLabel, lookup, lookupTone } from "@/lib/labels";
import styles from "./pages.module.css";
import local from "./containers.module.css";

type Row = {
  id: string; name: string; image: string; state: string; health: string | null; status: string;
  restart_count: number; restart_loop: boolean; oom_killed: boolean;
  cpu_pct: number; mem_used: number; mem_limit: number; cpu_history: number[]; mem_history: number[];
};

const HISTORY = 60;

/** Live container events carry no history, so each one appends a sample to the history we already have. */
function merge(prev: ContainerInfo[] | undefined, live: Omit<ContainerInfo, "history">[]): ContainerInfo[] | undefined {
  if (!prev) return prev;
  const now = Date.now();
  const byId = new Map(prev.map(c => [c.id, c]));
  return live.map(item => {
    const history = byId.get(item.id)?.history ?? [];
    return { ...item, history: [...history, { ts: now, cpu_pct: item.cpu_pct, mem_used: item.mem_used }].slice(-HISTORY) };
  });
}

function toRow(c: ContainerInfo): Row {
  return {
    id: c.id, name: c.name, image: c.image, state: c.state, health: c.health, status: c.status,
    restart_count: c.restart_count, restart_loop: c.restart_loop, oom_killed: c.oom_killed,
    cpu_pct: c.cpu_pct, mem_used: c.mem_used, mem_limit: c.mem_limit,
    cpu_history: c.history.map(h => h.cpu_pct), mem_history: c.history.map(h => h.mem_used),
  };
}

function horizon(containers: ContainerInfo[]) {
  const active = containers.filter(c => c.state === "running" && c.history.length > 1 && c.history.some(h => h.cpu_pct > 0));
  const length = Math.max(0, ...active.map(c => c.history.length));
  const reference = active.find(c => c.history.length === length);
  const days = (reference?.history ?? []).map(h => ({ short: formatTime(h.ts), long: formatDateTime(h.ts) }));
  const series = active.map(c => {
    const values = c.history.map(h => h.cpu_pct);
    const mean = values.reduce((sum, v) => sum + v, 0) / values.length || 1;
    const padded = Array.from({ length: length - values.length }, () => 0).concat(values.map(v => Math.round((v / mean - 1) * 100)));
    return { id: c.id, name: c.name, values: padded };
  });
  const every = Math.max(1, Math.round(length / 5));
  const ticks = days.flatMap((d, index) => (index % every === 0 ? [{ index, label: d.short }] : []));
  return { days, series, ticks };
}

export default function ContainersPage() {
  const [tab, setTab] = useState("monitor");
  const tabs = <SegmentedControl label="视图" options={[{ value: "monitor", label: "监控" }, { value: "manage", label: "管理" }]} value={tab} onValueChange={setTab} />;
  return tab === "monitor" ? <MonitorView tabs={tabs} /> : <DockerManage tabs={tabs} />;
}

function MonitorView({ tabs }: { tabs: ReactNode }) {
  const containers = useQuery(() => api.containers(), [], { refreshMs: 60_000 });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useStreamEvent("containers", live => containers.setData(prev => merge(prev, live)));

  const selected = containers.data?.find(c => c.id === selectedId) ?? null;
  const shown = useDrawerItem(selected);

  const columns: DataColumn<Row>[] = [
    {
      key: "name", label: "名称", sortable: true,
      render: (_v, row) => (
        <button type="button" className={local.nameButton} onClick={() => setSelectedId(row.id)} aria-label={`查看 ${row.name} 的详情与日志`}>
          <span className={styles.strong}>{row.name}</span>
          <span className={`${styles.muted} ${styles.small}`}>{row.image}</span>
        </button>
      ),
    },
    {
      key: "state", label: "状态", sortable: true,
      render: (_v, row) => (
        <div className={local.badges}>
          <Badge size="sm" tone={lookupTone(containerStateTone, row.state)} dot>{lookup(containerStateLabel, row.state)}</Badge>
          {row.health && <Badge size="sm" tone={row.health === "healthy" ? "success" : row.health === "unhealthy" ? "danger" : "neutral"}>{lookup(healthLabel, row.health)}</Badge>}
          {row.restart_loop && <Badge size="sm" tone="danger">重启循环</Badge>}
          {row.oom_killed && <Badge size="sm" tone="danger">内存溢出</Badge>}
        </div>
      ),
    },
    {
      key: "cpu_pct", label: "CPU", numeric: true, sortable: true,
      render: (_v, row) => (
        <div className={local.spark}>
          <Sparkline data={row.cpu_history.length > 1 ? row.cpu_history : [row.cpu_pct, row.cpu_pct]} label={`${row.name} CPU`} value={formatPercent(row.cpu_pct)} width={120} height={28} interactive={false} area={false} />
        </div>
      ),
    },
    {
      key: "mem_used", label: "内存", numeric: true, sortable: true,
      render: (_v, row) => (
        <div className={local.spark}>
          <Sparkline
            data={row.mem_history.length > 1 ? row.mem_history.map(b => b / 1024 / 1024) : [0, 0]}
            label={`${row.name} 内存`}
            value={formatBytes(row.mem_used)}
            tone={row.mem_limit > 0 && percentOf(row.mem_used, row.mem_limit) > 85 ? "warning" : "accent"}
            width={120}
            height={28}
            interactive={false}
            area={false}
          />
        </div>
      ),
    },
    { key: "restart_count", label: "重启次数", numeric: true, sortable: true, render: (_v, row) => <span className={row.restart_count > 5 ? styles.danger : undefined}>{row.restart_count}</span> },
    { key: "status", label: "Docker 状态", render: (_v, row) => <span className={`${styles.muted} ${styles.small}`}>{row.status}</span> },
  ];

  return (
    <>
      <PageHeader title="Docker" description="容器状态、资源占用与日志">{tabs}</PageHeader>

      <Section
        title="容器列表"
        description="点击容器名称查看详情与脱敏日志"
        query={containers}
        flush
        skeletonLines={8}
        isEmpty={data => data.length === 0}
        empty={{ title: "没有发现容器", description: "未检测到 Docker，或主机上没有容器。确认守护进程可以访问 Docker 套接字。" }}
      >
        {data => (
          <SortableDataTable<Row>
            rows={data.map(toRow)}
            rowKey="id"
            caption="容器列表"
            columns={columns}
            defaultSort={{ key: "cpu_pct", direction: "desc" }}
            emptyMessage="没有容器"
            itemName={{ one: "个容器", other: "个容器" }}
          />
        )}
      </Section>

      <ContainerCharts query={containers} />

      <Drawer open={selected !== null} onOpenChange={open => { if (!open) setSelectedId(null); }}>
        {shown && (
          <DrawerContent title={shown.name} description={shown.image} side="right">
            <ContainerDetail container={shown} />
          </DrawerContent>
        )}
      </Drawer>
    </>
  );
}

function ContainerCharts({ query }: { query: Query<ContainerInfo[]> }) {
  const data = query.data;
  const chart = useMemo(() => (data ? horizon(data) : null), [data]);
  const tree = useMemo(() => {
    const children = (data ?? []).filter(c => c.mem_used > 0).map(c => ({
      id: c.id, label: c.name, value: c.mem_used,
      color: c.mem_limit > 0 ? Math.round(percentOf(c.mem_used, c.mem_limit)) : 0,
    }));
    return { id: "all", label: "全部容器", children };
  }, [data]);

  return (
    <>
      {query.status === "ready" && chart && chart.series.length > 0 ? (
        <HorizonChart
          title="容器 CPU 波动"
          description="每个容器相对自身平均 CPU 的偏离，颜色越深偏离越大"
          series={chart.series}
          days={chart.days}
          ticks={chart.ticks}
          baselineLabel="各自平均值"
          defaultSort="peak"
          defaultBands={3}
        />
      ) : (
        <Panel title="容器 CPU 波动" busy={query.status === "loading"}>
          <QueryView query={query} skeletonLines={6} isEmpty={() => true} empty={{ title: "暂无 CPU 历史", description: "运行中的容器采集到几次样本后会显示波动图。" }}>
            {() => null}
          </QueryView>
        </Panel>
      )}

      <Panel title="内存占用分布" description="面积表示内存用量，颜色表示占内存上限的比例" busy={query.status === "loading"}>
        <QueryView
          query={query}
          skeletonLines={8}
          isEmpty={() => tree.children.length === 0}
          empty={{ title: "没有内存数据", description: "没有运行中的容器，或尚未采集到内存用量。" }}
        >
          {() => (
            <Treemap
              data={tree}
              label="容器内存占用"
              height={320}
              formatValue={v => formatBytes(v)}
              colorLabel="占上限比例"
              formatColor={v => `${v}%`}
              colorDomain={[0, 100]}
              emptyLabel="没有内存数据"
            />
          )}
        </QueryView>
      </Panel>
    </>
  );
}

function ContainerDetail({ container }: { container: ContainerInfo }) {
  const logs = useQuery(() => api.containerLogs(container.id, 200), [container.id]);
  const now = useNow();
  return (
    <div className={styles.stack}>
      <div className={local.badges}>
        <Badge size="sm" tone={lookupTone(containerStateTone, container.state)} dot>{lookup(containerStateLabel, container.state)}</Badge>
        {container.restart_loop && <Badge size="sm" tone="danger">重启循环</Badge>}
        {container.oom_killed && <Badge size="sm" tone="danger">内存溢出</Badge>}
      </div>
      <Facts
        items={[
          { label: "容器 ID", value: <code className={styles.code}>{container.id.slice(0, 12)}</code> },
          { label: "Docker 状态", value: container.status },
          { label: "启动时间", value: container.started_at ? formatRelative(container.started_at, now) : "-" },
          { label: "重启次数", value: container.restart_count },
          { label: "CPU", value: formatPercent(container.cpu_pct) },
          { label: "内存", value: container.mem_limit > 0 ? `${formatBytes(container.mem_used)} / ${formatBytes(container.mem_limit)}` : formatBytes(container.mem_used) },
          { label: "网络收", value: formatBytes(container.net_rx) },
          { label: "网络发", value: formatBytes(container.net_tx) },
        ]}
      />
      <h3 className={styles.subheading}>最近日志（已脱敏）</h3>
      <QueryView
        query={logs}
        skeletonLines={8}
        errorTitle="日志加载失败"
        isEmpty={data => data.lines.length === 0}
        empty={{ title: "没有日志", description: "该容器最近没有输出。" }}
      >
        {data => (
          <CodeBlock
            filename={`${container.name}.log`}
            language="log"
            maxLines={24}
            code={data.lines.map(line => `${line.ts ? formatTime(line.ts) : "--:--:--"} ${line.stream === "stderr" ? "ERR" : "OUT"} ${line.text}`).join("\n")}
          />
        )}
      </QueryView>
    </div>
  );
}
