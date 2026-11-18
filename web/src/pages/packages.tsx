import { useState } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { PackageJob, PackageOp, PackageUpdate, PackagesResponse } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { PageHeader, Panel, Section, errorMessage, useNow } from "@/components/panel";
import { formatDateTime, formatRelative } from "@/lib/format";
import { navigate } from "@/lib/router";
import styles from "./pages.module.css";
import local from "./settings.module.css";

const toError = (e: unknown) => errorMessage(e instanceof Error ? e : new Error(String(e)));

const OP_LABEL: Record<PackageOp, string> = {
  refresh: "刷新软件包索引",
  upgrade_security: "安装安全更新",
  upgrade_all: "升级全部软件包",
  upgrade_packages: "升级选中的软件包",
};
const JOB_TONE = { running: "info", succeeded: "success", failed: "danger", unknown: "warning" } as const;
const JOB_LABEL = { running: "进行中", succeeded: "完成", failed: "失败", unknown: "状态未知" } as const;

type Row = { key: string; manager: string; name: string; current: string; available: string; source: string; security: boolean };

function summary(r: PackagesResponse): string {
  const lines = r.packages.map(p => `${p.manager} ${p.name} ${p.current ?? "?"} -> ${p.available}${p.security ? "（安全更新）" : ""}${p.source ? ` [${p.source}]` : ""}`);
  return `检查时间：${r.checked_at ? formatDateTime(r.checked_at) : "未知"}\n包管理器：${r.managers.join(", ")}\n待更新 ${r.packages.length} 个：\n${lines.join("\n")}`;
}

export default function PackagesPage() {
  const now = useNow();
  const report = useQuery(() => api.packages(), []);
  const jobs = useQuery(() => api.packageJobs(), []);
  const [selected, setSelected] = useState<number | null>(null);
  const [live, setLive] = useState<Record<number, string>>({});
  const [checking, setChecking] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  useStreamEvent("package_job", e => {
    if (e.line !== null) setLive(l => ({ ...l, [e.id]: (l[e.id] ?? "") + e.line + "\n" }));
    if (e.status !== "running" || !jobs.data?.some(j => j.id === e.id)) {
      jobs.reload();
      if (e.status !== "running") report.reload();
    }
  });

  const recheck = async () => {
    setChecking(true);
    setError(null);
    try {
      const r = await api.checkPackages();
      report.setData(prev => prev && { ...r, updater: prev.updater });
    } catch (e) {
      setError(toError(e));
    } finally {
      setChecking(false);
    }
  };

  const start = async (op: PackageOp, names: string[] = []) => {
    const what = op === "upgrade_packages" ? `${OP_LABEL[op]}：${names.join(", ")}` : OP_LABEL[op];
    if (!window.confirm(`确认在这台服务器上执行「${what}」？\n升级可能会重启相关服务，建议在维护窗口进行。`)) return;
    setError(null);
    try {
      const { id } = await api.startPackageJob(op, names);
      setPicked([]);
      setSelected(id);
      setLive(l => ({ ...l, [id]: "" }));
      jobs.reload();
    } catch (e) {
      setError(toError(e));
    }
  };

  const ask = async () => {
    if (!report.data) return;
    try {
      const { id } = await api.createConversation({
        title: "软件包更新咨询",
        context: { text: summary(report.data) },
        message: "请评估这些待更新软件包的风险：哪些是安全更新、哪些可能需要重启服务或主机，给出建议的升级顺序和注意事项。",
      });
      navigate(`/agent/${id}`);
    } catch (e) {
      setError(toError(e));
    }
  };

  const canApply = Boolean(report.data?.updater?.available) && !report.data?.in_container;
  const running = jobs.data?.some(j => j.status === "running") ?? false;

  const columns: DataColumn<Row>[] = [
    { key: "name", label: "软件包", sortable: true, render: (_v, r) => <span className={styles.row}><code className={styles.code}>{r.name}</code>{r.security && <Badge size="sm" tone="danger">安全</Badge>}</span> },
    { key: "manager", label: "来源", sortable: true },
    { key: "current", label: "当前版本", render: (_v, r) => <code className={styles.code}>{r.current}</code> },
    { key: "available", label: "可用版本", render: (_v, r) => <code className={styles.code}>{r.available}</code> },
    { key: "source", label: "仓库", sortable: true, render: (_v, r) => <span className={`${styles.small} ${styles.muted}`}>{r.source}</span> },
    {
      key: "key", label: "", render: (_v, r) => r.manager === "brew"
        ? <span className={`${styles.small} ${styles.muted}`}>仅查看</span>
        : <Button size="sm" variant="ghost" disabled={!canApply || running} onClick={() => start("upgrade_packages", [r.name])}>升级</Button>,
    },
  ];
  const rows = (pkgs: PackageUpdate[]): Row[] => pkgs.map(p => ({
    key: `${p.manager}:${p.name}`, manager: p.manager, name: p.name, current: p.current ?? "-", available: p.available, source: p.source ?? "", security: p.security,
  }));

  const r = report.data;
  // Homebrew is list-only; the helper upgrades apt/dnf packages
  const pickedNames = picked.filter(k => !k.startsWith("brew:")).map(k => k.slice(k.indexOf(":") + 1));
  const security = r?.packages.filter(p => p.security).length ?? 0;

  return (
    <>
      <PageHeader title="软件更新" description="apt / dnf / Homebrew 的待更新软件包；列表基于本机已有索引，不会自动刷新或安装">
        <Button variant="secondary" onClick={ask} disabled={!r || r.packages.length === 0}>问 Agent</Button>
        <Button onClick={recheck} loading={checking}>重新检查</Button>
      </PageHeader>

      {error && <Alert tone="danger" title="操作失败" onDismiss={() => setError(null)}>{error}</Alert>}
      {r?.in_container && <Alert tone="warning" title="运行在容器中">这里列出的是容器镜像中的软件包，不是宿主机；升级操作已禁用。</Alert>}
      {r && !r.in_container && !r.updater?.available && (
        <Alert tone="info" title="只读模式">
          没有检测到更新助手（{r.updater?.socket}），只能查看更新。如需在这里执行升级，请按 deploy/tsmonitor-updater.service 中的说明安装助手；Homebrew 始终只查看。
        </Alert>
      )}
      {r && r.errors.length > 0 && <Alert tone="warning" title="部分检查失败">{r.errors.join("；")}</Alert>}

      <Section
        title={r ? `待更新 ${r.packages.length} 个${security ? `，其中安全更新 ${security} 个` : ""}` : "待更新"}
        description={r?.checked_at ? `${r.managers.join(" / ") || "未检测到包管理器"} · 检查于 ${formatRelative(r.checked_at, now)}` : "首次检查在启动后约 90 秒进行"}
        actions={canApply && (
          <div className={local.rowActions}>
            <Button size="sm" variant="secondary" disabled={running} onClick={() => start("refresh")}>刷新索引</Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={running || pickedNames.length === 0}
              onClick={() => start("upgrade_packages", pickedNames)}
            >
              升级选中{pickedNames.length ? `（${pickedNames.length}）` : ""}
            </Button>
            <Button size="sm" variant="secondary" disabled={running || security === 0} onClick={() => start("upgrade_security")}>安装安全更新</Button>
            <Button size="sm" variant="danger" disabled={running || (r?.packages.length ?? 0) === 0} onClick={() => start("upgrade_all")}>全部升级</Button>
          </div>
        )}
        query={report}
        flush
        isEmpty={d => d.packages.length === 0}
        empty={{ title: "没有待更新的软件包", description: "如果很久没有刷新索引，结果可能不完整。" }}
      >
        {d => (
          <SortableDataTable<Row>
            rows={rows(d.packages)}
            columns={columns}
            rowKey="key"
            caption="待更新软件包"
            selectable={canApply}
            selectedKeys={picked}
            onSelectionChange={setPicked}
            itemName={{ one: "个软件包", other: "个软件包" }}
          />
        )}
      </Section>

      <div className={styles.masterDetail}>
        <Section title="更新任务" query={jobs} isEmpty={d => d.length === 0} empty={{ title: "还没有任务", description: "执行刷新或升级后，任务记录会出现在这里。" }}>
          {d => (
            <ul className={styles.pickList}>
              {d.map(j => (
                <li key={j.id}>
                  <button type="button" className={styles.pick} aria-current={j.id === selected ? "true" : undefined} onClick={() => setSelected(j.id)}>
                    <span className={styles.between}>
                      <span className={styles.pickTitle}>{OP_LABEL[j.op]}</span>
                      <Badge size="sm" tone={JOB_TONE[j.status]} dot>{JOB_LABEL[j.status]}</Badge>
                    </span>
                    <span className={`${styles.muted} ${styles.small}`}>{formatRelative(j.started_at, now)}{j.packages.length ? ` · ${j.packages.join(", ")}` : ""}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Section>
        {selected !== null
          ? <JobLog key={selected} id={selected} live={live[selected]} />
          : <Panel title="任务日志"><p className={styles.textSecondary}>从左侧选择一个任务查看输出。</p></Panel>}
      </div>
    </>
  );
}

function JobLog({ id, live }: { id: number; live: string | undefined }) {
  const job = useQuery(() => api.packageJob(id), [id]);
  useStreamEvent("package_job", e => {
    if (e.id === id && e.status !== "running") job.reload();
  });
  const j: PackageJob | null = job.data ?? null;
  const text = j?.status === "running" ? (j.log ?? "") + (live ?? "") : j?.log ?? live ?? "";
  return (
    <Panel title={j ? OP_LABEL[j.op] : "任务日志"} description={j ? `开始于 ${formatDateTime(j.started_at)}${j.exit_code !== null ? ` · 退出码 ${j.exit_code}` : ""}` : undefined}>
      {text ? <CodeBlock code={text} language="log" filename={`job-${id}.log`} maxLines={30} /> : <p className={styles.textSecondary}>{j?.status === "running" ? "等待输出…" : "没有输出"}</p>}
    </Panel>
  );
}
