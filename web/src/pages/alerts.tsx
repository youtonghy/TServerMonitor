import { useState } from "react";
import { Alert as Notice } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { Select } from "@/components/arc/select/select";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { Alert, Severity } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { PageHeader, Section, errorMessage, useNow } from "@/components/panel";
import { formatDateTime, formatRelative } from "@/lib/format";
import { alertSourceLabel, lookup, severityLabel, severityTone } from "@/lib/labels";
import { Link, navigate } from "@/lib/router";
import styles from "./pages.module.css";
import local from "./settings.module.css";

const STATUS = [
  { value: "open", label: "未处理" },
  { value: "all", label: "全部" },
];
const SEVERITY = [
  { value: "any", label: "全部级别" },
  { value: "critical", label: "严重" },
  { value: "warning", label: "警告" },
  { value: "info", label: "提示" },
];
const SILENCE = [
  { value: "60", label: "静默 1 小时" },
  { value: "240", label: "静默 4 小时" },
  { value: "1440", label: "静默 1 天" },
  { value: "10080", label: "静默 7 天" },
];

const RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

const toError = (e: unknown) => errorMessage(e instanceof Error ? e : new Error(String(e)));

export default function AlertsPage() {
  const now = useNow(15_000);
  const [status, setStatus] = useState<"open" | "all">("open");
  const [severity, setSeverity] = useState("any");
  const alerts = useQuery(() => api.alerts(status, 200), [status]);
  const [error, setError] = useState<string | null>(null);

  useStreamEvent("alert", alert => {
    alerts.setData(prev => {
      if (!prev) return prev;
      const rest = prev.filter(a => a.id !== alert.id);
      if (status === "open" && alert.status !== "open") return rest;
      return [alert, ...rest];
    });
  });

  const update = (next: Alert) => alerts.setData(prev => prev && (status === "open" && next.status !== "open"
    ? prev.filter(a => a.id !== next.id)
    : prev.map(a => (a.id === next.id ? next : a))));

  const run = async (action: () => Promise<Alert>) => {
    setError(null);
    try {
      update(await action());
    } catch (e) {
      setError(toError(e));
    }
  };

  const ask = async (a: Alert) => {
    try {
      const { id } = await api.createConversation({ title: `告警：${a.title}`, context: { alert_id: a.id } });
      navigate(`/agent/${id}`);
    } catch (e) {
      setError(toError(e));
    }
  };

  const visible = (list: Alert[]) => list
    .filter(a => severity === "any" || a.severity === severity)
    .sort((x, y) => (x.status === y.status ? 0 : x.status === "open" ? -1 : 1) || RANK[x.severity] - RANK[y.severity] || y.last_seen - x.last_seen);

  return (
    <>
      <PageHeader title="告警" description="确认、静默或关闭告警；通知渠道在设置页配置">
        <SegmentedControl label="状态" options={STATUS} value={status} onValueChange={v => setStatus(v as "open" | "all")} />
        <Link to="/wall">打开大屏</Link>
      </PageHeader>
      {error && <Notice tone="danger" title="操作失败" onDismiss={() => setError(null)}>{error}</Notice>}
      <Section
        title="告警列表"
        description="已确认的告警只有在升级时才会再次通知；静默期间同一来源的新告警也不通知。"
        actions={<div className={local.filterSelect}><Select label="级别" options={SEVERITY} value={severity} onValueChange={setSeverity} /></div>}
        query={alerts}
        isEmpty={d => visible(d).length === 0}
        empty={{ title: "没有告警", description: status === "open" ? "当前没有未处理的告警。" : "还没有任何告警记录。" }}
      >
        {d => (
          <ul className={styles.list}>
            {visible(d).map(a => {
              const silenced = a.silenced_until !== null && a.silenced_until > now;
              return (
                <li key={a.id} className={local.providerRow}>
                  <div className={local.providerMain}>
                    <div className={styles.row}>
                      <Badge size="sm" tone={severityTone[a.severity]} dot>{severityLabel[a.severity]}</Badge>
                      <p className={styles.itemTitle}>#{a.id} {a.title}</p>
                    </div>
                    <p className={styles.textSecondary}>{a.summary}</p>
                    {a.suggestion && <p className={styles.textSecondary}>建议：{a.suggestion}</p>}
                    <div className={local.badges}>
                      <Badge size="sm">{lookup(alertSourceLabel, a.source)}</Badge>
                      {a.status === "resolved" && <Badge size="sm" tone="success">已恢复</Badge>}
                      {a.acked_at && <Badge size="sm" tone="info">已确认</Badge>}
                      {silenced && <Badge size="sm" tone="warning">静默至 {formatDateTime(a.silenced_until!)}</Badge>}
                      <span className={`${styles.muted} ${styles.small}`}>
                        首次 {formatRelative(a.created_at, now)} · 最近 {formatRelative(a.last_seen, now)} · 共 {a.count} 次{a.notified ? " · 已通知" : ""}
                      </span>
                    </div>
                  </div>
                  <div className={local.rowActions}>
                    {a.status === "open" && !a.acked_at && <Button size="sm" variant="secondary" onClick={() => run(() => api.ackAlert(a.id))}>确认</Button>}
                    {a.status === "open" && (silenced
                      ? <Button size="sm" variant="ghost" onClick={() => run(() => api.silenceAlert(a.id, 0))}>取消静默</Button>
                      : <div className={local.inlineSelect}><Select label="静默" options={SILENCE} placeholder="静默…" value="" onValueChange={v => run(() => api.silenceAlert(a.id, Number(v)))} /></div>)}
                    {a.status === "open" && <Button size="sm" variant="ghost" onClick={() => run(() => api.closeAlert(a.id))}>关闭</Button>}
                    <Button size="sm" variant="ghost" onClick={() => ask(a)}>问 Agent</Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </Section>
    </>
  );
}
