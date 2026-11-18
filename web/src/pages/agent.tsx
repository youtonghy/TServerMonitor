import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { JsonViewer } from "@/components/arc/json-viewer/json-viewer";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { Textarea } from "@/components/arc/textarea/textarea";
import { ApiError, api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { AgentRunDetail, AgentStep, Conversation, ConversationContext } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { PageHeader, Panel, QueryView, Section, errorMessage, useNow } from "@/components/panel";
import { formatDateTime, formatElapsed, formatRelative } from "@/lib/format";
import { lookup, runStatusLabel, runStatusTone, taskKindLabel, triggerLabel } from "@/lib/labels";
import { Link, navigate, useRoute } from "@/lib/router";
import styles from "./pages.module.css";
import local from "./agent.module.css";

type Filter = "" | "chat" | "task";
const FILTERS: { value: string; label: string }[] = [
  { value: "", label: "全部" },
  { value: "chat", label: "对话" },
  { value: "task", label: "自动任务" },
];

const toError = (e: unknown) => errorMessage(e instanceof Error ? e : new Error(String(e)));

export default function AgentPage() {
  const route = useRoute();
  const now = useNow(5_000);
  const [filter, setFilter] = useState<Filter>("");
  const list = useQuery(() => api.conversations(filter, 100), [filter]);

  // old links pointed at runs; every run now lives in conversation "c_<run id>"
  const segment = route.segments[1] ?? null;
  useEffect(() => {
    if (segment?.startsWith("run_")) navigate(`/agent/c_${segment}`, { replace: true });
  }, [segment]);

  useStreamEvent("agent", event => {
    if (!event.conversation_id) return;
    const known = list.data?.some(c => c.id === event.conversation_id);
    if (!known || event.step?.kind === "user") {
      list.reload();
      return;
    }
    list.setData(prev => prev?.map(c => c.id === event.conversation_id ? { ...c, last_status: event.status, updated_at: Date.now() } : c));
  });

  const selected = segment && !segment.startsWith("run_") ? segment : null;

  return (
    <>
      <PageHeader title="Agent 控制台" description="所有 Agent 会话：自动任务的分析过程，以及你和 Agent 的对话">
        <SegmentedControl label="会话类型" options={FILTERS} value={filter} onValueChange={v => setFilter(v as Filter)} />
        <Button onClick={() => navigate("/agent/new")}>新对话</Button>
      </PageHeader>
      <div className={styles.masterDetail}>
        <Section
          title="会话"
          query={list}
          skeletonLines={8}
          isEmpty={data => data.length === 0}
          empty={{ title: "还没有会话", description: "点击“新对话”向 Agent 提问，或等待定时巡检运行。" }}
        >
          {data => <ConversationList items={data} selected={selected} now={now} />}
        </Section>
        {selected === "new" || !selected
          ? <NewConversationPanel onCreated={id => { list.reload(); navigate(`/agent/${id}`); }} />
          : <ConversationView key={selected} id={selected} now={now} onDeleted={() => { list.reload(); navigate("/agent"); }} />}
      </div>
    </>
  );
}

function ConversationList({ items, selected, now }: { items: Conversation[]; selected: string | null; now: number }) {
  return (
    <ul className={styles.pickList}>
      {items.map(c => (
        <li key={c.id}>
          <Link to={`/agent/${c.id}`} className={styles.pick} aria-current={c.id === selected ? "page" : undefined}>
            <span className={styles.between}>
              <span className={styles.pickTitle}>{c.title}</span>
              {c.last_status && <Badge size="sm" tone={runStatusTone[c.last_status]} dot>{runStatusLabel[c.last_status]}</Badge>}
            </span>
            <span className={`${styles.muted} ${styles.small}`}>
              {lookup(taskKindLabel, c.kind)} · {formatRelative(c.updated_at, now)}{c.kind === "chat" ? ` · ${c.runs} 轮` : ""}
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------- composer

function Composer({ busy, disabled, onSend, onCancel, placeholder }: {
  busy: boolean; disabled?: boolean; placeholder?: string;
  onSend: (text: string) => Promise<void>; onCancel?: () => void;
}) {
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    const value = text.trim();
    if (!value || busy || sending) return;
    setSending(true);
    try {
      await onSend(value);
      setText("");
    } catch {
      // the caller shows the error and keeps the draft
    } finally {
      setSending(false);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      void submit();
    }
  };

  return (
    <form className={local.composer} onSubmit={submit}>
      <Textarea
        label="消息"
        value={text}
        onChange={e => setText(e.target.value)}
        onKeyDown={onKeyDown}
        placeholder={placeholder ?? "向 Agent 提问，例如：最近一小时有什么异常？"}
        rows={3}
        maxLength={8000}
        disabled={disabled}
        description="Ctrl/⌘ + Enter 发送。Agent 只能读取数据和给出建议，不会修改服务器。"
      />
      <div className={local.composerActions}>
        {busy && onCancel && <Button type="button" variant="ghost" onClick={onCancel}>停止</Button>}
        <Button type="submit" loading={sending} disabled={busy || disabled || !text.trim()}>发送</Button>
      </div>
    </form>
  );
}

function NewConversationPanel({ onCreated }: { onCreated: (id: string) => void }) {
  const [error, setError] = useState<string | null>(null);
  return (
    <Panel title="新对话" description="可以询问系统状态、日志、告警原因或优化建议。Agent 会按需调用工具读取数据。">
      <div className={styles.stack}>
        {error && <Alert tone="danger" title="无法开始对话" onDismiss={() => setError(null)}>{error}</Alert>}
        <Composer
          busy={false}
          onSend={async text => {
            try {
              const { id } = await api.createConversation({ message: text });
              onCreated(id);
            } catch (e) {
              setError(toError(e));
              throw e;
            }
          }}
        />
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------- conversation

function ConversationView({ id, now, onDeleted }: { id: string; now: number; onDeleted: () => void }) {
  const detail = useQuery(() => api.conversation(id), [id]);
  const [streams, setStreams] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const bottom = useRef<HTMLDivElement>(null);

  useStreamEvent("agent", event => {
    if (event.conversation_id !== id) return;
    const known = detail.data?.runs.some(r => r.id === event.run_id);
    if (!known || event.status !== "running") {
      detail.reload(); // new run, or final state with finished_at / error / report
      if (event.status !== "running") setStreams(s => omit(s, event.run_id));
      return;
    }
    if (!event.step) return;
    const step = event.step;
    detail.setData(prev => prev && {
      ...prev,
      runs: prev.runs.map(r => r.id !== event.run_id || r.steps.some(s => s.seq === step.seq)
        ? r
        : { ...r, steps: [...r.steps, step], steps_count: r.steps.length + 1 }),
    });
    // the streamed text is now persisted as a message
    if (step.kind === "message") setStreams(s => omit(s, event.run_id));
  });

  useStreamEvent("agent_delta", event => {
    if (event.conversation_id !== id) return;
    setStreams(s => ({ ...s, [event.run_id]: (s[event.run_id] ?? "") + event.text }));
  });

  const stepCount = detail.data?.runs.reduce((n, r) => n + r.steps.length, 0) ?? 0;
  const streamLength = Object.values(streams).reduce((n, t) => n + t.length, 0);
  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "nearest" });
  }, [stepCount, streamLength]);

  const running = detail.data?.runs.find(r => r.status === "running") ?? null;

  const send = async (text: string) => {
    setError(null);
    try {
      await api.sendMessage(id, text);
      detail.reload();
    } catch (e) {
      setError(e instanceof ApiError && e.status === 409 ? "Agent 正在处理上一条消息，或同时进行的对话已达上限，请稍后再试" : toError(e));
      throw e;
    }
  };

  const cancel = async () => {
    if (!running) return;
    try {
      await api.cancelRun(running.id);
    } catch (e) {
      setError(toError(e));
    }
  };

  const remove = async () => {
    if (!window.confirm("删除这个对话及其全部消息？")) return;
    try {
      await api.deleteConversation(id);
      onDeleted();
    } catch (e) {
      setError(toError(e));
    }
  };

  return (
    <Panel
      title={detail.data?.title ?? "会话"}
      description={detail.data ? `${lookup(taskKindLabel, detail.data.kind)} · 创建于 ${formatDateTime(detail.data.created_at)}` : undefined}
      actions={detail.data?.kind === "chat" ? <Button size="sm" variant="ghost" onClick={remove}>删除</Button> : undefined}
    >
      <QueryView query={detail} skeletonLines={8} errorTitle="会话加载失败">
        {data => (
          <div className={styles.stack}>
            {data.context && <ContextNote context={data.context} />}
            <div className={local.thread} aria-live="polite">
              {data.runs.length === 0 && <p className={styles.textSecondary}>还没有消息。</p>}
              {data.runs.map(run => <RunBlock key={run.id} run={run} stream={streams[run.id]} now={now} />)}
              <div ref={bottom} />
            </div>
            {error && <Alert tone="danger" title="发送失败" onDismiss={() => setError(null)}>{error}</Alert>}
            <Composer
              busy={running !== null}
              onSend={send}
              onCancel={cancel}
              placeholder={data.kind === "chat" ? undefined : "针对这次自动分析继续追问，例如：第一条建议具体怎么改？"}
            />
          </div>
        )}
      </QueryView>
    </Panel>
  );
}

function ContextNote({ context }: { context: ConversationContext }) {
  if ("report_id" in context) return <p className={styles.textSecondary}>本对话围绕 <Link to={`/reports/${context.report_id}`}>报告 #{context.report_id}</Link></p>;
  if ("alert_id" in context) return <p className={styles.textSecondary}>本对话围绕告警 #{context.alert_id}</p>;
  if ("run_id" in context) return <p className={styles.textSecondary}>本对话围绕运行 {context.run_id}</p>;
  return <p className={styles.textSecondary}>本对话附带了一份上下文资料</p>;
}

/** Pairs each tool call with its result so they render as one collapsible item. */
type ToolPair = { type: "tool"; call: AgentStep; result: AgentStep | null };
type Item = { type: "step"; step: AgentStep } | ToolPair;

function items(steps: AgentStep[]): Item[] {
  const out: Item[] = [];
  for (const step of [...steps].sort((a, b) => a.seq - b.seq)) {
    if (step.kind === "tool_result") {
      const open = [...out].reverse().find((i): i is ToolPair => i.type === "tool" && i.result === null && i.call.tool === step.tool);
      if (open) open.result = step;
      else out.push({ type: "tool", call: { ...step, kind: "tool_call", input: null }, result: step });
    } else if (step.kind === "tool_call") {
      out.push({ type: "tool", call: step, result: null });
    } else {
      out.push({ type: "step", step });
    }
  }
  return out;
}

function RunBlock({ run, stream, now }: { run: AgentRunDetail; stream: string | undefined; now: number }) {
  const chat = run.kind === "chat";
  return (
    <section className={local.run} aria-label={chat ? "对话轮次" : "自动任务运行"}>
      {!chat && (
        <div className={local.runHeader}>
          <span className={styles.row}>
            <Badge size="sm">{lookup(taskKindLabel, run.kind)}</Badge>
            <Badge size="sm" tone={runStatusTone[run.status]} dot>{runStatusLabel[run.status]}</Badge>
            <span className={`${styles.muted} ${styles.small}`}>
              {lookup(triggerLabel, run.trigger)}触发 · {formatDateTime(run.started_at)} · 耗时 {formatElapsed(run.started_at, run.finished_at, now)} · {run.model ?? "规则引擎"}
            </span>
          </span>
          {run.report_id && <Link to={`/reports/${run.report_id}`}>查看报告 #{run.report_id}</Link>}
        </div>
      )}
      {items(run.steps).map(item => item.type === "tool"
        ? <ToolItem key={item.call.seq} call={item.call} result={item.result} />
        : <StepItem key={item.step.seq} step={item.step} chat={chat} />)}
      {run.status === "running" && (
        <div className={local.assistant}>
          {stream ? <p className={local.bubbleText}>{stream}</p> : <p className={`${styles.muted} ${styles.small}`}>Agent 正在思考…</p>}
        </div>
      )}
      {run.status === "cancelled" && <p className={`${styles.muted} ${styles.small}`}>已停止</p>}
      {run.status === "fallback" && run.error && <p className={`${styles.muted} ${styles.small}`}>已改用规则引擎：{run.error}</p>}
    </section>
  );
}

function StepItem({ step, chat }: { step: AgentStep; chat: boolean }) {
  if (step.kind === "user") {
    return <div className={local.user}><p className={local.bubbleText}>{step.text}</p></div>;
  }
  if (step.kind === "error") {
    return <Alert tone="danger" title="运行出错">{step.text}</Alert>;
  }
  // in scheduled runs intermediate messages are the model's working notes
  return (
    <div className={chat ? local.assistant : local.note}>
      <p className={local.bubbleText}>{step.text}</p>
    </div>
  );
}

function ToolItem({ call, result }: { call: AgentStep; result: AgentStep | null }) {
  const failed = Boolean(result?.output && typeof result.output === "object" && "error" in (result.output as object));
  return (
    <details className={local.tool}>
      <summary>
        <span className={styles.row}>
          <code className={styles.code}>{call.tool}</code>
          {result ? <Badge size="sm" tone={failed ? "danger" : "success"}>{failed ? "失败" : "完成"}</Badge> : <Badge size="sm" tone="info">执行中</Badge>}
        </span>
      </summary>
      <div className={styles.stack}>
        {call.input !== null && call.input !== undefined && <JsonViewer data={call.input} rootName="input" defaultExpandDepth={2} maxHeight={240} label={`${call.tool ?? "工具"} 输入`} />}
        {result && <JsonViewer data={result.output} rootName="output" defaultExpandDepth={1} maxHeight={320} label={`${call.tool ?? "工具"} 输出`} />}
      </div>
    </details>
  );
}

function omit<T>(record: Record<string, T>, key: string): Record<string, T> {
  if (!(key in record)) return record;
  const next = { ...record };
  delete next[key];
  return next;
}
