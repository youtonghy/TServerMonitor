import { useState } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { RadarChart } from "@/components/arc-pro/radar-chart/radar-chart";
import { ApiError, api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { Diagnosis, Priority, Report, ReportKind, ReportSummary } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { PageHeader, Panel, Section, errorMessage, useNow } from "@/components/panel";
import { formatDateTime, formatRelative } from "@/lib/format";
import {
  categoryLabel, confidenceLabel, confidenceTone, dimensionLabel, findingSeverityLabel, findingSeverityTone, generatedByLabel,
  priorityLabel, priorityTone, reportKindLabel, severityLabel, severityTone,
} from "@/lib/labels";
import { Link, navigate, useRoute } from "@/lib/router";
import styles from "./pages.module.css";

const KINDS: { value: ReportKind | "all"; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "hourly", label: "小时" },
  { value: "daily", label: "日报" },
  { value: "incident", label: "事件" },
  { value: "audit", label: "审计" },
];

const DIMENSIONS = ["cpu", "memory", "disk", "logs", "security", "containers", "database"] as const;

type TriggerState =
  | { status: "idle" }
  | { status: "started"; runId: string }
  | { status: "busy"; runId: string | null }
  | { status: "error"; message: string };

function scoreTone(score: number) {
  return score >= 80 ? "success" : score >= 60 ? "warning" : "danger";
}

export default function ReportsPage() {
  const route = useRoute();
  const now = useNow();
  const [kind, setKind] = useState<ReportKind | "all">("all");
  const reports = useQuery(() => api.reports(kind === "all" ? "" : kind, 50), [kind]);
  const [trigger, setTrigger] = useState<TriggerState>({ status: "idle" });
  const [triggering, setTriggering] = useState(false);

  useStreamEvent("report", summary => {
    if (kind === "all" || summary.kind === kind) reports.setData(prev => prev && [summary, ...prev.filter(r => r.id !== summary.id)]);
  });

  const routeId = route.segments[1] ? Number(route.segments[1]) : null;
  const selectedId = routeId ?? reports.data?.[0]?.id ?? null;

  const runNow = async () => {
    setTriggering(true);
    const triggerKind: ReportKind = kind === "all" ? "hourly" : kind;
    try {
      const { run_id } = await api.trigger(triggerKind);
      setTrigger({ status: "started", runId: run_id });
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        const status = await api.status().catch(() => null);
        setTrigger({ status: "busy", runId: status?.ai.running ?? null });
      } else {
        setTrigger({ status: "error", message: errorMessage(error instanceof Error ? error : new Error(String(error))) });
      }
    } finally {
      setTriggering(false);
    }
  };

  return (
    <>
      <PageHeader title="报告" description="巡检与诊断报告，包含根因、安全风险与建议">
        <SegmentedControl label="报告类型" options={KINDS} value={kind} onValueChange={value => setKind(value as ReportKind | "all")} />
        <Button onClick={runNow} loading={triggering}>
          {trigger.status === "started" ? "巡检已开始" : "立即巡检"}
        </Button>
      </PageHeader>

      {trigger.status === "started" && (
        <Alert tone="success" title="巡检已开始" onDismiss={() => setTrigger({ status: "idle" })}>
          完成后报告会自动出现在列表中。<Link to={`/agent/${trigger.runId}`}>查看运行过程</Link>
        </Alert>
      )}
      {trigger.status === "busy" && (
        <Alert tone="warning" title="已有巡检正在进行" onDismiss={() => setTrigger({ status: "idle" })}>
          同一时间只能运行一次巡检，请等待当前运行结束。{trigger.runId && <Link to={`/agent/${trigger.runId}`}>查看正在进行的运行</Link>}
        </Alert>
      )}
      {trigger.status === "error" && (
        <Alert tone="danger" title="无法开始巡检" onDismiss={() => setTrigger({ status: "idle" })}>
          {trigger.message}
        </Alert>
      )}

      <div className={styles.masterDetail}>
        <Section
          title="报告列表"
          query={reports}
          skeletonLines={8}
          isEmpty={data => data.length === 0}
          empty={{ title: "没有报告", description: kind === "all" ? "点击“立即巡检”生成第一份报告。" : "该类型暂无报告，换一个类型看看。" }}
        >
          {data => <ReportList reports={data} selectedId={selectedId} now={now} />}
        </Section>

        {selectedId !== null
          ? <ReportDetail key={selectedId} id={selectedId} />
          : reports.status === "ready" && <Panel title="报告详情"><p className={styles.textSecondary}>从左侧选择一份报告。</p></Panel>}
      </div>
    </>
  );
}

function ReportList({ reports, selectedId, now }: { reports: ReportSummary[]; selectedId: number | null; now: number }) {
  return (
    <ul className={styles.pickList}>
      {reports.map(report => (
        <li key={report.id}>
          <Link to={`/reports/${report.id}`} className={styles.pick} aria-current={report.id === selectedId ? "page" : undefined}>
            <span className={styles.between}>
              <span className={styles.pickTitle}>{report.title}</span>
              <Badge size="sm" tone={scoreTone(report.health_score)}>{report.health_score}</Badge>
            </span>
            <span className={`${styles.muted} ${styles.small}`}>
              {reportKindLabel[report.kind]} · {generatedByLabel[report.generated_by]} · {formatRelative(report.created_at, now)}
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

/** Opens a conversation about this report in the Agent console. */
function AskAgent({ reportId, title }: { reportId: number; title?: string }) {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const ask = async () => {
    setBusy(true);
    setFailed(null);
    try {
      const { id } = await api.createConversation({ title: `追问：${title ?? `报告 #${reportId}`}`, context: { report_id: reportId } });
      navigate(`/agent/${id}`);
    } catch (error) {
      setFailed(errorMessage(error instanceof Error ? error : new Error(String(error))));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Button size="sm" variant="secondary" onClick={ask} loading={busy} title={failed ?? undefined}>
      {failed ? "无法创建对话" : "向 Agent 追问"}
    </Button>
  );
}

function ReportDetail({ id }: { id: number }) {
  const report = useQuery(() => api.report(id), [id]);
  return (
    <div className={styles.stack}>
      <Section title="报告摘要" query={report} skeletonLines={6} errorTitle="报告加载失败" actions={<AskAgent reportId={id} title={report.data?.title} />}>
        {data => <Summary report={data} />}
      </Section>
      {report.status === "ready" && <Diagnoses body={report.data.body} />}
    </div>
  );
}

function Summary({ report }: { report: Report }) {
  return (
    <div className={styles.stack}>
      <div className={styles.between}>
        <p className={styles.itemTitle}>{report.title}</p>
        <div className={styles.row}>
          <Badge size="sm">{reportKindLabel[report.kind]}</Badge>
          <Badge size="sm" tone={scoreTone(report.health_score)}>健康评分 {report.health_score}</Badge>
        </div>
      </div>
      <p className={styles.text}>{report.body.summary || report.summary}</p>
      <p className={styles.textSecondary}>
        {formatDateTime(report.created_at)} 由{generatedByLabel[report.generated_by]}生成{report.model ? `（${report.model}）` : ""}
        {report.run_id && <> · <Link to={`/agent/${report.run_id}`}>查看运行过程</Link></>}
      </p>
    </div>
  );
}

const PRIORITIES: Priority[] = ["high", "medium", "low"];

function Diagnoses({ body }: { body: Diagnosis }) {
  return (
    <>
      <Panel title="健康维度" description="各维度 0 到 100 分，越高越健康">
        <RadarChart
          axes={DIMENSIONS.map(key => ({ key, label: dimensionLabel[key] }))}
          series={[{ key: "score", label: "本次评分", values: { ...body.dimensions } }]}
          label="健康维度评分"
          max={100}
          size={320}
          formatValue={value => `${Math.round(value)} 分`}
          emptyLabel="没有维度数据"
        />
      </Panel>

      <Panel title="根因分析">
        {body.root_causes.length === 0 ? <p className={styles.textSecondary}>未发现明确根因。</p> : (
          <ul className={styles.list}>
            {body.root_causes.map((cause, i) => (
              <li key={i}>
                <div className={styles.between}>
                  <p className={styles.itemTitle}>{cause.title}</p>
                  <Badge size="sm" tone={confidenceTone[cause.confidence]}>{confidenceLabel[cause.confidence]}</Badge>
                </div>
                <p className={styles.textSecondary}>证据：{cause.evidence}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="建议">
        {body.recommendations.length === 0 ? <p className={styles.textSecondary}>暂无建议。</p> : PRIORITIES.map(priority => {
          const items = body.recommendations.filter(r => r.priority === priority);
          if (!items.length) return null;
          return (
            <section key={priority} className={styles.stack} aria-label={priorityLabel[priority]}>
              <h3 className={styles.subheading}><Badge size="sm" tone={priorityTone[priority]}>{priorityLabel[priority]}</Badge></h3>
              <ul className={styles.list}>
                {items.map((rec, i) => (
                  <li key={i}>
                    <div className={styles.between}>
                      <p className={styles.itemTitle}>{rec.title}</p>
                      <Badge size="sm" outline>{categoryLabel[rec.category]}</Badge>
                    </div>
                    <p className={styles.text}>{rec.detail}</p>
                    <p className={styles.textSecondary}>预期效果：{rec.expected_impact}</p>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </Panel>

      <div className={styles.grid2}>
        <Panel title="安全风险">
          {body.security_risks.length === 0 ? <p className={styles.textSecondary}>未发现安全风险。</p> : (
            <ul className={styles.list}>
              {body.security_risks.map((risk, i) => (
                <li key={i}>
                  <div className={styles.between}>
                    <p className={styles.itemTitle}>{risk.title}</p>
                    <Badge size="sm" tone={findingSeverityTone[risk.severity]}>{findingSeverityLabel[risk.severity]}</Badge>
                  </div>
                  <p className={styles.textSecondary}>{risk.detail}</p>
                  <p className={styles.text}>建议：{risk.recommendation}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="异常">
          {body.anomalies.length === 0 ? <p className={styles.textSecondary}>未发现异常。</p> : (
            <ul className={styles.list}>
              {body.anomalies.map((anomaly, i) => (
                <li key={i}>
                  <div className={styles.between}>
                    <p className={styles.itemTitle}>{anomaly.title}</p>
                    <Badge size="sm" tone={severityTone[anomaly.severity]}>{severityLabel[anomaly.severity]}</Badge>
                  </div>
                  <p className={styles.textSecondary}>{anomaly.detail}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </>
  );
}
