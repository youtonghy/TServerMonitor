import { useState } from "react";
import { Badge } from "@/components/arc/badge/badge";
import { DonutChart } from "@/components/arc/donut-chart/donut-chart";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { Switch } from "@/components/arc/switch/switch";
import { api } from "@/api/client";
import type { DbStatus, Finding, FindingSeverity, PortInfo } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { Facts, PageHeader, Section, useNow } from "@/components/panel";
import { formatDateTime, formatDuration, formatNumber, formatRelative } from "@/lib/format";
import { findingCategoryLabel, findingSeverityLabel, findingSeverityOrder, findingSeverityTone, lookup } from "@/lib/labels";
import styles from "./pages.module.css";

const severityColor: Record<FindingSeverity, string> = {
  critical: "var(--danger)",
  high: "var(--warning)",
  medium: "var(--series-3)",
  low: "var(--series-1)",
  info: "var(--series-4)",
};

type PortRow = { key: string; proto: string; addr: string; port: number; process: string; exposed: boolean };

const dbMetricLabel: Record<string, string> = {
  connections: "连接数", max_connections: "最大连接数", threads_running: "运行线程", qps: "每秒查询",
  slow_queries: "慢查询总数", uptime_secs: "运行时长", innodb_buffer_pool_hit_pct: "缓冲池命中率",
  replication_lag_secs: "复制延迟", active_connections: "活跃连接", deadlocks: "死锁", cache_hit_pct: "缓存命中率",
};

function formatDbMetric(key: string, value: number): string {
  if (key.endsWith("_secs")) return key === "uptime_secs" ? formatDuration(value) : `${formatNumber(value)} 秒`;
  if (key.endsWith("_pct")) return `${formatNumber(value)}%`;
  return formatNumber(value);
}

export default function SecurityPage() {
  const now = useNow();
  const [includeResolved, setIncludeResolved] = useState(false);
  const findings = useQuery(() => api.findings(includeResolved), [includeResolved], { refreshMs: 120_000 });
  const ports = useQuery(() => api.ports(), [], { refreshMs: 120_000 });
  const db = useQuery(() => api.db(), [], { refreshMs: 60_000 });

  const portColumns: DataColumn<PortRow>[] = [
    { key: "port", label: "端口", numeric: true, sortable: true, render: (_v, row) => <span className={row.exposed ? styles.exposedRow : styles.strong}>{row.port}</span> },
    { key: "proto", label: "协议", sortable: true, render: (_v, row) => (row.proto === "udp" ? "UDP" : "TCP") },
    { key: "addr", label: "监听地址", sortable: true, render: (_v, row) => <code className={styles.code}>{row.addr}</code> },
    { key: "process", label: "进程", sortable: true },
    {
      key: "exposed", label: "暴露情况", sortable: true,
      render: (_v, row) => row.exposed ? <Badge size="sm" tone="danger" dot>对外暴露</Badge> : <Badge size="sm" tone="neutral">仅本机或内网</Badge>,
    },
  ];

  return (
    <>
      <PageHeader title="安全" description="安全发现、监听端口与数据库状态" />

      <div className={styles.split}>
        <Section
          title="安全发现"
          query={findings}
          skeletonLines={10}
          actions={<Switch label="显示已解决" checked={includeResolved} onCheckedChange={setIncludeResolved} />}
          isEmpty={data => data.length === 0}
          empty={{ title: "没有安全发现", description: "最近一次审计没有发现问题。空闲窗口时会再次审计。" }}
        >
          {data => <FindingList findings={data} now={now} />}
        </Section>

        <Section
          title="按严重程度"
          query={findings}
          skeletonLines={6}
          isEmpty={data => data.length === 0}
          empty={{ title: "没有数据", description: "出现安全发现后会显示分布。" }}
        >
          {data => (
            <DonutChart
              data={findingSeverityOrder.map(severity => ({
                key: severity,
                label: findingSeverityLabel[severity],
                value: data.filter(f => f.severity === severity).length,
                color: severityColor[severity],
              })).filter(d => d.value > 0)}
              label="安全发现按严重程度"
              unit="项"
              totalLabel="发现"
              size={200}
              formatValue={v => formatNumber(v)}
              emptyLabel="没有数据"
            />
          )}
        </Section>
      </div>

      <Section
        title="监听端口"
        description="对外暴露的端口以红色标出"
        query={ports}
        flush
        skeletonLines={8}
        isEmpty={data => data.length === 0}
        empty={{ title: "没有监听端口", description: "未发现处于监听状态的端口。" }}
      >
        {data => (
          <SortableDataTable<PortRow>
            rows={data.map(toPortRow)}
            rowKey="key"
            caption="监听端口"
            columns={portColumns}
            defaultSort={{ key: "exposed", direction: "desc" }}
            emptyMessage="没有监听端口"
            itemName={{ one: "个端口", other: "个端口" }}
          />
        )}
      </Section>

      <Section
        title="数据库"
        query={db}
        skeletonLines={6}
        isEmpty={data => data.length === 0}
        empty={{ title: "未配置数据库", description: "在配置文件中添加 MySQL 或 PostgreSQL 连接后会显示其状态。" }}
      >
        {data => (
          <div className={styles.grid2}>
            {data.map(item => <DbCard key={item.name} db={item} now={now} />)}
          </div>
        )}
      </Section>
    </>
  );
}

function toPortRow(p: PortInfo): PortRow {
  return { key: `${p.proto}-${p.addr}-${p.port}`, proto: p.proto, addr: p.addr, port: p.port, process: p.process ?? "未知", exposed: p.exposed };
}

function FindingList({ findings, now }: { findings: Finding[]; now: number }) {
  const sorted = [...findings].sort((a, b) =>
    Number(a.resolved) - Number(b.resolved)
    || findingSeverityOrder.indexOf(a.severity) - findingSeverityOrder.indexOf(b.severity)
    || b.last_seen - a.last_seen);
  return (
    <ul className={styles.list}>
      {sorted.map(f => (
        <li key={f.id}>
          <div className={styles.row}>
            <Badge size="sm" tone={findingSeverityTone[f.severity]}>{findingSeverityLabel[f.severity]}</Badge>
            <Badge size="sm" outline>{lookup(findingCategoryLabel, f.category)}</Badge>
            {f.resolved && <Badge size="sm" tone="success">已解决</Badge>}
          </div>
          <p className={styles.itemTitle}>{f.title}</p>
          <p className={styles.textSecondary}>{f.detail}</p>
          {f.evidence && <code className={`${styles.code} ${styles.muted}`}>{f.evidence}</code>}
          <p className={`${styles.textSecondary} ${styles.small}`}>
            首次发现 {formatDateTime(f.first_seen)}，最近 {formatRelative(f.last_seen, now)}
          </p>
        </li>
      ))}
    </ul>
  );
}

function DbCard({ db, now }: { db: DbStatus; now: number }) {
  const metrics = Object.entries(db.metrics);
  return (
    <article className={styles.statusCard} aria-label={`数据库 ${db.name}`}>
      <div className={styles.between}>
        <p className={styles.itemTitle}>{db.name}</p>
        <div className={styles.row}>
          <Badge size="sm" outline>{db.kind === "mysql" ? "MySQL" : "PostgreSQL"}</Badge>
          <Badge size="sm" tone={db.ok ? "success" : "danger"} dot>{db.ok ? "连接正常" : "连接失败"}</Badge>
        </div>
      </div>
      {db.error && <p className={`${styles.textSecondary} ${styles.danger}`}>{db.error}</p>}
      {metrics.length > 0
        ? <Facts items={metrics.map(([key, value]) => ({ label: dbMetricLabel[key] ?? key, value: formatDbMetric(key, value) }))} />
        : !db.error && <p className={styles.textSecondary}>没有可用指标</p>}
      <p className={`${styles.textSecondary} ${styles.small}`}>采样于 {formatRelative(db.ts, now)}</p>
    </article>
  );
}
