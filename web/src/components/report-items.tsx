import { useState, type FormEvent, type KeyboardEvent, type ReactNode } from "react";
import { MessageCircleQuestion, PanelRightOpen, Sparkles, Wrench } from "lucide-react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge, type BadgeTone } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Drawer, DrawerContent, useDrawerItem } from "@/components/arc/drawer/drawer";
import { Textarea } from "@/components/arc/textarea/textarea";
import { Tooltip } from "@/components/arc/tooltip/tooltip";
import { ApiError, api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { ChangeRequest, Diagnosis, ItemIntent, ReportConversation, ReportConversations, ReportSection } from "@/api/types";
import { useQuery, type Query } from "@/api/useQuery";
import { formatRelative } from "@/lib/format";
import {
  categoryLabel, confidenceLabel, findingSeverityLabel, priorityLabel, runStatusLabel, severityLabel,
} from "@/lib/labels";
import { Link } from "@/lib/router";
import { ChangeRequestCard } from "./change-requests";
import { QueryView, errorMessage, useNow } from "./panel";
import styles from "@/pages/pages.module.css";
import local from "./report-items.module.css";

const sectionLabel: Record<ReportSection, string> = {
  root_causes: "根因", recommendations: "建议", security_risks: "安全风险", anomalies: "异常",
};
const intentLabel: Record<ItemIntent, string> = { explain: "解释", ask: "追问", fix: "修复" };

export interface ItemRef { section: ReportSection; index: number; title: string }

function toError(e: unknown): string {
  if (e instanceof ApiError && e.status === 409) return "Agent 正忙，后台排队已满，请稍后再试";
  return errorMessage(e instanceof Error ? e : new Error(String(e)));
}

function itemOf(ctx: ReportConversation["context"]): { section: ReportSection; index: number; intent?: ItemIntent } | null {
  if (!ctx || !("report_id" in ctx) || !ctx.item) return null;
  return { ...ctx.item, intent: ctx.intent };
}

/** Conversations (oldest first) and change requests about one item. */
function threadsFor(data: ReportConversations | undefined, item: ItemRef) {
  const conversations = (data?.conversations ?? []).filter(c => {
    const i = itemOf(c.context);
    return i?.section === item.section && i.index === item.index;
  });
  const ids = new Set(conversations.map(c => c.id));
  const requests = (data?.requests ?? []).filter(r => r.conversation_id && ids.has(r.conversation_id));
  return { conversations, requests };
}

function status(c: ReportConversation): { label: string; tone: BadgeTone } {
  if (c.queued) return { label: "排队中", tone: "neutral" };
  if (!c.last_status) return { label: "排队中", tone: "neutral" };
  if (c.last_status === "running") return { label: "分析中", tone: "info" };
  return { label: runStatusLabel[c.last_status], tone: c.last_status === "succeeded" ? "success" : c.last_status === "failed" ? "danger" : "neutral" };
}

function prompt(intent: ItemIntent, item: ItemRef): string {
  const what = `${sectionLabel[item.section]}「${item.title}」`;
  return intent === "fix"
    ? `请帮我修复这一条${what}。先确认问题是否仍然存在，能通过面板完成的改动请逐项提交变更申请，其他需要我手动做的步骤列出来。`
    : `请详细解释这一条${what}：它是什么、证据从哪里来、影响有多大，以及为什么这样建议。`;
}

/**
 * Report-level state for item actions: the conversations started from this report, kept fresh
 * by the agent and approval events.
 */
export function useReportThreads(reportId: number) {
  const threads = useQuery(() => api.reportConversations(reportId), [reportId]);
  useStreamEvent("agent", e => {
    const c = threads.data?.conversations.find(x => x.id === e.conversation_id);
    // a queued message starting, or a run finishing
    if (c && (e.status !== "running" || c.last_status !== "running" || c.queued)) threads.reload();
  });
  useStreamEvent("approval", () => threads.reload());
  return threads;
}

/** Starts a background conversation about one item; returns its id. */
async function startThread(reportId: number, item: ItemRef, intent: ItemIntent, message: string): Promise<string> {
  const { id } = await api.createConversation({
    title: `${intentLabel[intent]}：${item.title}`.slice(0, 60),
    context: { report_id: reportId, item: { section: item.section, index: item.index }, intent },
    message,
  });
  return id;
}

/** A square icon button with its name in a tooltip and for screen readers. */
function IconAction({ label, icon, loading, onClick }: { label: string; icon: ReactNode; loading?: boolean; onClick: () => void }) {
  return (
    <Tooltip content={label}>
      <Button size="sm" variant="secondary" className={local.iconButton} aria-label={label} loading={loading} onClick={onClick}>
        {icon}
      </Button>
    </Tooltip>
  );
}

/** Buttons and live status under one report item. */
export function ItemActions({ reportId, item, threads, onOpen }: {
  reportId: number; item: ItemRef; threads: Query<ReportConversations>; onOpen: (item: ItemRef) => void;
}) {
  const [busy, setBusy] = useState<ItemIntent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { conversations, requests } = threadsFor(threads.data, item);
  const latest = conversations.at(-1);
  const waiting = requests.filter(r => r.status === "pending").length;

  const start = async (intent: ItemIntent) => {
    setBusy(intent);
    setError(null);
    try {
      await startThread(reportId, item, intent, prompt(intent, item));
      threads.reload();
    } catch (e) {
      setError(toError(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className={local.actions}>
      <span className={local.tools} role="group" aria-label={`${item.title} 的操作`}>
        <IconAction label="查看详情" icon={<PanelRightOpen />} onClick={() => onOpen(item)} />
        <IconAction label="让 Agent 解释" icon={<Sparkles />} loading={busy === "explain"} onClick={() => void start("explain")} />
        <IconAction label="追问" icon={<MessageCircleQuestion />} onClick={() => onOpen(item)} />
        <IconAction label="让 Agent 修复" icon={<Wrench />} loading={busy === "fix"} onClick={() => void start("fix")} />
      </span>
      <span className={styles.row}>
        {latest && (
          <button type="button" className={local.statusLink} onClick={() => onOpen(item)}>
            <Badge size="sm" tone={status(latest).tone} dot>{intentLabel[itemOf(latest.context)?.intent ?? "ask"]} · {status(latest).label}</Badge>
          </button>
        )}
        {waiting > 0 && <Link to="/approvals"><Badge size="sm" tone="warning">{waiting} 项变更待批准</Badge></Link>}
        {error && <span className={`${styles.danger} ${styles.small}`} role="alert">{error}</span>}
      </span>
    </div>
  );
}

/** Every field of the item, by section. */
function ItemBody({ body, item }: { body: Diagnosis; item: ItemRef }) {
  const rows: [string, string][] = [];
  if (item.section === "root_causes") {
    const c = body.root_causes[item.index];
    if (c) rows.push(["证据", c.evidence], ["置信度", confidenceLabel[c.confidence]]);
  } else if (item.section === "recommendations") {
    const r = body.recommendations[item.index];
    if (r) rows.push(["内容", r.detail], ["预期效果", r.expected_impact], ["分类", categoryLabel[r.category]], ["优先级", priorityLabel[r.priority]]);
  } else if (item.section === "security_risks") {
    const r = body.security_risks[item.index];
    if (r) rows.push(["详情", r.detail], ["建议", r.recommendation], ["严重程度", findingSeverityLabel[r.severity]]);
  } else {
    const a = body.anomalies[item.index];
    if (a) rows.push(["详情", a.detail], ["严重程度", severityLabel[a.severity]]);
  }
  return (
    <dl className={local.facts}>
      {rows.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Latest assistant answer of a conversation, live. */
function LatestAnswer({ id }: { id: string }) {
  const conv = useQuery(() => api.conversation(id), [id]);
  useStreamEvent("agent", e => {
    if (e.conversation_id === id && (e.status !== "running" || e.step?.kind === "message")) conv.reload();
  });
  return (
    <QueryView query={conv} skeletonLines={4} errorTitle="对话加载失败">
      {data => {
        const run = data.runs.at(-1);
        const answer = run?.steps.filter(s => s.kind === "message").at(-1)?.text;
        if (data.queued) return <p className={styles.textSecondary}>排队中，前面的对话完成后自动开始。</p>;
        if (run?.status === "running") return <p className={styles.textSecondary}>{answer ? <span className={local.answer}>{answer}</span> : "Agent 正在分析…"}</p>;
        if (run?.status === "failed") return <Alert tone="danger" title="分析失败">{run.error ?? "未知错误"}</Alert>;
        return answer ? <p className={local.answer}>{answer}</p> : <p className={styles.textSecondary}>还没有回答。</p>;
      }}
    </QueryView>
  );
}

function AskBox({ onSend, busy }: { onSend: (text: string) => Promise<void>; busy: boolean }) {
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    const value = text.trim();
    if (!value || sending || busy) return;
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
    <form className={styles.stack} onSubmit={submit}>
      <Textarea
        label="追问"
        value={text}
        onChange={e => setText(e.target.value)}
        onKeyDown={onKeyDown}
        rows={3}
        maxLength={8000}
        placeholder="例如：这条建议具体改哪个文件？会不会影响现有访问？"
        description="Ctrl/⌘ + Enter 发送。在后台运行，可以关闭抽屉稍后回来看。"
      />
      <span className={styles.row}>
        <Button type="submit" size="sm" loading={sending} disabled={busy || !text.trim()}>发送</Button>
      </span>
    </form>
  );
}

/** Side panel for one item: full content, the agent's latest answer, follow-up, and its change requests. */
export function ItemDrawer({ reportId, body, item, threads, onClose }: {
  reportId: number; body: Diagnosis; item: ItemRef | null; threads: Query<ReportConversations>; onClose: () => void;
}) {
  const shown = useDrawerItem(item);
  const now = useNow();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<ItemIntent | null>(null);
  const { conversations, requests } = shown ? threadsFor(threads.data, shown) : { conversations: [], requests: [] as ChangeRequest[] };
  const latest = conversations.at(-1);
  const latestBusy = latest ? latest.queued || latest.last_status === "running" || !latest.last_status : false;

  const start = async (intent: ItemIntent, message?: string) => {
    if (!shown) return;
    setBusy(intent);
    setError(null);
    try {
      await startThread(reportId, shown, intent, message ?? prompt(intent, shown));
      threads.reload();
    } catch (e) {
      setError(toError(e));
      throw e;
    } finally {
      setBusy(null);
    }
  };

  // a follow-up continues the latest thread about this item
  const ask = async (text: string) => {
    if (!latest) return start("ask", text);
    setError(null);
    try {
      await api.sendMessage(latest.id, text);
      threads.reload();
    } catch (e) {
      setError(toError(e));
      throw e;
    }
  };

  return (
    <Drawer open={item !== null} onOpenChange={open => { if (!open) onClose(); }}>
      {shown && (
        <DrawerContent title={shown.title} description={`报告 #${reportId} · ${sectionLabel[shown.section]}`} side="right">
          <div className={styles.stack}>
            <ItemBody body={body} item={shown} />
            <span className={styles.row}>
              <Button size="sm" variant="secondary" loading={busy === "explain"} onClick={() => void start("explain").catch(() => undefined)}>让 Agent 解释</Button>
              <Button size="sm" loading={busy === "fix"} onClick={() => void start("fix").catch(() => undefined)}>让 Agent 修复</Button>
            </span>
            {error && <Alert tone="danger" title="无法开始" onDismiss={() => setError(null)}>{error}</Alert>}

            {latest && (
              <section className={styles.stack} aria-label="Agent 的回答">
                <div className={styles.between}>
                  <h3 className={styles.subheading}>Agent 的回答</h3>
                  <Link to={`/agent/${latest.id}`}>打开完整对话</Link>
                </div>
                <LatestAnswer key={latest.id} id={latest.id} />
              </section>
            )}

            <AskBox onSend={ask} busy={latestBusy} />

            {requests.length > 0 && (
              <section className={styles.stack} aria-label="变更申请">
                <h3 className={styles.subheading}>变更申请</h3>
                <ul className={styles.list}>
                  {requests.map(r => <li key={r.id}><ChangeRequestCard request={r} onChanged={() => threads.reload()} showLink={false} /></li>)}
                </ul>
              </section>
            )}

            {conversations.length > 0 && (
              <section className={styles.stack} aria-label="相关对话">
                <h3 className={styles.subheading}>相关对话</h3>
                <ul className={styles.list}>
                  {[...conversations].reverse().map(c => (
                    <li key={c.id}>
                      <div className={styles.between}>
                        <Link to={`/agent/${c.id}`}>{c.title}</Link>
                        <span className={styles.row}>
                          <Badge size="sm" tone={status(c).tone} dot>{status(c).label}</Badge>
                          <span className={`${styles.muted} ${styles.small}`}>{formatRelative(c.updated_at, now)}</span>
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </div>
        </DrawerContent>
      )}
    </Drawer>
  );
}
