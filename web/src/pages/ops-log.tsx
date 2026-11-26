import { useState } from "react";
import { Badge } from "@/components/arc/badge/badge";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { AuditEntry } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { OpsJobLog } from "@/components/job-log";
import { JOB_LABEL, JOB_TONE } from "@/components/ops";
import { PageHeader, Panel, Section, useNow } from "@/components/panel";
import { formatDateTime, formatRelative } from "@/lib/format";
import styles from "./pages.module.css";

const DOMAINS = [
  { value: "", label: "全部" }, { value: "docker", label: "Docker" }, { value: "nginx", label: "nginx" },
  { value: "firewall", label: "防火墙" }, { value: "ssh", label: "SSH" }, { value: "pending", label: "确认/撤销" },
];
const OUTCOME_TONE = { started: "info", succeeded: "success", failed: "danger", refused: "warning" } as const;
const OUTCOME_LABEL = { started: "进行中", succeeded: "成功", failed: "失败", refused: "被拒绝" } as const;

type AuditRow = AuditEntry & Record<string, unknown>;

export default function OpsLogPage() {
  const now = useNow();
  const [domain, setDomain] = useState("");
  const jobs = useQuery(() => api.opsJobs(domain || undefined, 50), [domain]);
  const audit = useQuery(() => api.opsAudit(200), []);
  const [selected, setSelected] = useState<number | null>(null);

  useStreamEvent("ops_job", e => {
    if (e.status !== "running" || !jobs.data?.some(j => j.id === e.id)) {
      jobs.reload();
      audit.reload();
    }
  });

  const columns: DataColumn<AuditRow>[] = [
    { key: "ts", label: "时间", sortable: true, render: (_v, r) => <span className={styles.small}>{formatDateTime(r.ts)}</span> },
    { key: "via", label: "来源", sortable: true, render: (_v, r) => <span className={styles.small}>{r.via === "mcp" ? "外部 Agent" : "面板"}{r.remote ? ` · ${r.remote}` : ""}</span> },
    { key: "summary", label: "操作", render: (_v, r) => <span className={styles.row}><span className={styles.small}>{r.summary}</span>{r.dry_run && <Badge size="sm" tone="neutral" outline>演练</Badge>}</span> },
    { key: "outcome", label: "结果", sortable: true, render: (_v, r) => <Badge size="sm" tone={OUTCOME_TONE[r.outcome]} dot>{OUTCOME_LABEL[r.outcome]}</Badge> },
    { key: "detail", label: "说明", render: (_v, r) => <span className={`${styles.small} ${styles.muted}`}>{r.detail ?? ""}</span> },
  ];

  return (
    <>
      <PageHeader title="运维记录" description="面板与外部 Agent 通过运维助手执行的全部操作；助手另在 journald 中记录自己的审计日志">
        <SegmentedControl label="按类别筛选" options={DOMAINS} value={domain} onValueChange={setDomain} />
      </PageHeader>

      <div className={styles.masterDetail}>
        <Section title="任务" query={jobs} isEmpty={d => d.length === 0} empty={{ title: "还没有任务", description: "在 Docker、nginx、防火墙或 SSH 页面执行操作后会出现在这里。" }}>
          {d => (
            <ul className={styles.pickList}>
              {d.map(j => (
                <li key={j.id}>
                  <button type="button" className={styles.pick} aria-current={j.id === selected ? "true" : undefined} onClick={() => setSelected(j.id)}>
                    <span className={styles.between}>
                      <span className={styles.pickTitle}>{j.summary}</span>
                      <Badge size="sm" tone={JOB_TONE[j.status]} dot>{JOB_LABEL[j.status]}</Badge>
                    </span>
                    <span className={`${styles.muted} ${styles.small}`}>
                      {formatRelative(j.started_at, now)} · {j.via === "mcp" ? "外部 Agent" : "面板"}{j.dry_run ? " · 演练" : ""}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Section>
        {selected !== null
          ? <OpsJobLog key={selected} id={selected} />
          : <Panel title="任务日志"><p className={styles.textSecondary}>从左侧选择一个任务查看输出。</p></Panel>}
      </div>

      <Section title="审计日志" description="每次修改请求一行，包括被拒绝的请求" query={audit} flush isEmpty={d => d.length === 0} empty={{ title: "没有记录", description: "还没有任何修改请求。" }}>
        {d => <SortableDataTable<AuditRow> rows={d as AuditRow[]} columns={columns} rowKey="id" caption="审计日志" defaultSort={{ key: "ts", direction: "desc" }} />}
      </Section>
    </>
  );
}
