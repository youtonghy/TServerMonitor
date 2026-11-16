import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { JsonViewer } from "@/components/arc/json-viewer/json-viewer";
import { Timeline, type TimelineEvent } from "@/components/arc/timeline/timeline";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { AgentRun, AgentRunDetail, AgentStep } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { Facts, PageHeader, Panel, Section, useNow } from "@/components/panel";
import { formatDateTime, formatElapsed, formatRelative } from "@/lib/format";
import { lookup, reportKindLabel, runStatusLabel, runStatusTone, stepKindLabel, triggerLabel } from "@/lib/labels";
import { Link, useRoute } from "@/lib/router";
import styles from "./pages.module.css";

const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

export default function AgentPage() {
  const route = useRoute();
  const now = useNow(5_000);
  const runs = useQuery(() => api.agentRuns(50), []);

  useStreamEvent("agent", event => {
    const known = runs.data?.some(r => r.id === event.run_id);
    if (!known) {
      runs.reload();
      return;
    }
    runs.setData(prev => prev?.map(r => r.id === event.run_id
      ? { ...r, status: event.status, steps_count: event.step ? Math.max(r.steps_count, event.step.seq) : r.steps_count, finished_at: event.status === "running" ? null : r.finished_at ?? Date.now() }
      : r));
  });

  const selectedId = route.segments[1] ?? runs.data?.[0]?.id ?? null;

  return (
    <>
      <PageHeader title="Agent" description="AI 运维顾问的运行记录、工具调用与消息" />
      <div className={styles.masterDetail}>
        <Section
          title="运行记录"
          query={runs}
          skeletonLines={8}
          isEmpty={data => data.length === 0}
          empty={{ title: "还没有运行记录", description: "定时巡检或在报告页点击“立即巡检”后会出现在这里。", action: <Link to="/reports">前往报告</Link> }}
        >
          {data => <RunList runs={data} selectedId={selectedId} now={now} />}
        </Section>
        {selectedId
          ? <RunDetail key={selectedId} id={selectedId} now={now} />
          : runs.status === "ready" && <Panel title="运行详情"><p className={styles.textSecondary}>从左侧选择一次运行。</p></Panel>}
      </div>
    </>
  );
}

function RunList({ runs, selectedId, now }: { runs: AgentRun[]; selectedId: string | null; now: number }) {
  return (
    <ul className={styles.pickList}>
      {runs.map(run => (
        <li key={run.id}>
          <Link to={`/agent/${run.id}`} className={styles.pick} aria-current={run.id === selectedId ? "page" : undefined}>
            <span className={styles.between}>
              <span className={styles.pickTitle}>{reportKindLabel[run.kind]}</span>
              <Badge size="sm" tone={runStatusTone[run.status]} dot>{runStatusLabel[run.status]}</Badge>
            </span>
            <span className={`${styles.muted} ${styles.small}`}>
              {lookup(triggerLabel, run.trigger)}触发 · {formatRelative(run.started_at, now)} · {run.steps_count} 步
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

function stepTitle(step: AgentStep): string {
  const kind = stepKindLabel[step.kind];
  return step.tool ? `${kind}：${step.tool}` : kind;
}

function stepEvents(steps: AgentStep[]): TimelineEvent[] {
  return [...steps].sort((a, b) => b.seq - a.seq).map(step => {
    const payload = step.kind === "tool_call" ? step.input : step.kind === "tool_result" ? step.output : null;
    return {
      id: String(step.seq),
      at: step.ts,
      actor: `第 ${step.seq} 步`,
      title: stepTitle(step),
      meta: step.text && step.kind !== "error" ? step.text.slice(0, 60) + (step.text.length > 60 ? "…" : "") : undefined,
      tone: step.kind === "error" ? "danger" : step.kind === "tool_result" ? "success" : "neutral",
      detail: (
        <div className={styles.stack}>
          {step.text && <p className={styles.text}>{step.text}</p>}
          {payload !== null && payload !== undefined && (
            <JsonViewer
              data={payload}
              rootName={step.kind === "tool_call" ? "input" : "output"}
              defaultExpandDepth={2}
              maxHeight={320}
              label={step.kind === "tool_call" ? `${step.tool ?? "工具"} 输入` : `${step.tool ?? "工具"} 输出`}
            />
          )}
        </div>
      ),
    };
  });
}

function RunDetail({ id, now }: { id: string; now: number }) {
  const run = useQuery(() => api.agentRun(id), [id]);

  useStreamEvent("agent", event => {
    if (event.run_id !== id) return;
    if (event.status !== "running") {
      run.reload(); // Final state carries finished_at, report_id, and error.
      return;
    }
    run.setData(prev => {
      if (!prev) return prev;
      const steps = event.step && !prev.steps.some(s => s.seq === event.step!.seq) ? [...prev.steps, event.step] : prev.steps;
      return { ...prev, status: event.status, steps, steps_count: steps.length } satisfies AgentRunDetail;
    });
  });

  return (
    <div className={styles.stack}>
      <Section title="运行详情" query={run} skeletonLines={5} errorTitle="运行详情加载失败">
        {data => (
          <div className={styles.stack}>
            <div className={styles.row}>
              <Badge tone={runStatusTone[data.status]} dot>{runStatusLabel[data.status]}</Badge>
              <code className={`${styles.code} ${styles.muted}`}>{data.id}</code>
            </div>
            {data.error && <Alert tone={data.status === "fallback" ? "warning" : "danger"} title={data.status === "fallback" ? "已改用规则引擎" : "运行失败"}>{data.error}</Alert>}
            <Facts
              items={[
                { label: "类型", value: reportKindLabel[data.kind] },
                { label: "触发方式", value: lookup(triggerLabel, data.trigger) },
                { label: "开始时间", value: formatDateTime(data.started_at) },
                { label: "耗时", value: formatElapsed(data.started_at, data.finished_at, now) + (data.finished_at ? "" : "（进行中）") },
                { label: "模型", value: data.model ?? "规则引擎" },
                { label: "报告", value: data.report_id ? <Link to={`/reports/${data.report_id}`}>查看报告 #{data.report_id}</Link> : "-" },
              ]}
            />
          </div>
        )}
      </Section>

      <Section
        title="步骤"
        description="最新的步骤在最上方，展开可查看工具输入与输出"
        query={run}
        skeletonLines={8}
        isEmpty={data => data.steps.length === 0}
        empty={{ title: "没有步骤", description: "这次运行没有调用模型，可能直接使用了规则引擎。" }}
      >
        {data => (
          <Timeline
            events={stepEvents(data.steps)}
            now={now}
            label="运行步骤"
            locale="zh-CN"
            timeZone={timeZone}
            headingLevel={3}
            defaultExpanded={data.steps.length ? [String(Math.max(...data.steps.map(s => s.seq)))] : []}
          />
        )}
      </Section>
    </div>
  );
}
