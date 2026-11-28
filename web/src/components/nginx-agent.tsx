// In-site Agent helpers: structured config/site drafting box and live site assistant chat.
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { Sparkles } from "lucide-react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { JsonViewer } from "@/components/arc/json-viewer/json-viewer";
import { Select } from "@/components/arc/select/select";
import { Textarea } from "@/components/arc/textarea/textarea";
import { ApiError, api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { AgentRunDetail, AgentStep, NginxSite, SiteSpec } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ChangeRequestCard } from "@/components/change-requests";
import { QueryView, errorMessage, useNow } from "@/components/panel";
import { formatDateTime, formatElapsed, formatRelative } from "@/lib/format";
import { lookup, runStatusLabel, runStatusTone, taskKindLabel } from "@/lib/labels";
import { Link } from "@/lib/router";
import agentStyles from "@/pages/agent.module.css";
import pageStyles from "@/pages/pages.module.css";
import siteStyles from "./nginx-site.module.css";

const toError = (e: unknown) => {
  if (e instanceof ApiError && e.status === 409) return "Agent 正在处理其他消息或排队已满，请稍后再试";
  return errorMessage(e instanceof Error ? e : new Error(String(e)));
};

export interface DraftSuggestion {
  label: string;
  prompt: string;
}

interface DraftBoxProps {
  mode: "site" | "file";
  siteName?: string;
  spec?: SiteSpec;
  path?: string;
  content?: string;
  disabled?: boolean;
  title?: string;
  description?: string;
  placeholder?: string;
  suggestions?: DraftSuggestion[];
  onApplySite?: (spec: SiteSpec) => void;
  onApplyFile?: (content: string) => void;
  canUndo?: boolean;
  onUndo?: () => void;
}

export function NginxDraftBox({
  mode,
  siteName,
  spec,
  path,
  content,
  disabled,
  title = "让代理撰写配置",
  description = "描述你的目标，代理会读取本机状态和现有配置，自动生成并填入下方；保存前仍可预览和修改。",
  placeholder,
  suggestions = [],
  onApplySite,
  onApplyFile,
  canUndo,
  onUndo,
}: DraftBoxProps) {
  const [instruction, setInstruction] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<{ summary: string; warning: string | null; conversationId: string } | null>(null);

  const runDraft = async () => {
    const text = instruction.trim();
    if (!text || busy || disabled) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.draftNginx({
        mode,
        instruction: text,
        site_name: siteName,
        spec,
        path,
        content,
      });
      if (res.mode === "site") onApplySite?.(res.spec);
      else onApplyFile?.(res.content);
      setOutcome({ summary: res.summary, warning: res.warning, conversationId: res.conversation_id });
    } catch (e) {
      setError(toError(e));
    } finally {
      setBusy(false);
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void runDraft();
    }
  };

  return (
    <div className={siteStyles.draftBox}>
      <div className={siteStyles.draftHead}>
        <span className={siteStyles.draftTitle}>
          <Sparkles size={15} strokeWidth={1.75} aria-hidden="true" />
          <span>{title}</span>
        </span>
        <span className={`${pageStyles.muted} ${pageStyles.small}`}>Ctrl/⌘ + Enter 触发</span>
      </div>
      <p className={pageStyles.textSecondary}>{description}</p>
      {suggestions.length > 0 && (
        <div className={siteStyles.draftChips}>
          {suggestions.map(s => (
            <button
              key={s.label}
              type="button"
              className={siteStyles.chip}
              disabled={busy || disabled}
              onClick={() => setInstruction(s.prompt)}
            >
              {s.label}
            </button>
          ))}
        </div>
      )}
      <Textarea
        label="需求说明"
        value={instruction}
        onChange={e => setInstruction(e.target.value)}
        onKeyDown={onKeyDown}
        rows={2}
        maxLength={4000}
        disabled={busy || disabled}
        placeholder={placeholder ?? (mode === "site"
          ? "例如：将 api.example.com 反代到本机 4000 端口，开启 WebSocket 和自动 HTTPS，并屏蔽 /.env 扫描"
          : "例如：添加安全响应头，禁止访问 /.env 和 /.git，并优化静态资源缓存")}
      />
      <div className={siteStyles.draftActions}>
        {canUndo && onUndo && (
          <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={onUndo}>撤销代理撰写</Button>
        )}
        <Button type="button" size="sm" variant="secondary" loading={busy} disabled={disabled || !instruction.trim()} onClick={runDraft}>
          由代理撰写
        </Button>
      </div>
      {error && <Alert tone="danger" title="撰写失败" onDismiss={() => setError(null)}>{error}</Alert>}
      {outcome && (
        <Alert tone={outcome.warning ? "warning" : "info"} title="代理已撰写内容" onDismiss={() => setOutcome(null)}>
          <div className={pageStyles.stack}>
            {outcome.summary && <p className={pageStyles.text}>{outcome.summary}</p>}
            {outcome.warning && <p className={pageStyles.textSecondary}>{outcome.warning}</p>}
            <span className={siteStyles.draftOutcomeLinks}>
              <Link to={`/agent/${outcome.conversationId}`}>查看代理执行过程</Link>
              {canUndo && onUndo && (
                <Button type="button" size="sm" variant="ghost" onClick={onUndo}>撤销此次撰写</Button>
              )}
            </span>
          </div>
        </Alert>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- site assistant chat

interface SiteAgentPanelProps {
  site: NginxSite;
  onApplied?: () => void;
}

export function SiteAgentPanel({ site, onApplied }: SiteAgentPanelProps) {
  const now = useNow(5_000);
  const threads = useQuery(() => api.nginxSiteConversations(site.name), [site.name]);
  const [pickedId, setPickedId] = useState<string | null>(null);
  const [draftText, setDraftText] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const conversations = threads.data?.conversations ?? [];
  const activeId = pickedId === "new"
    ? null
    : pickedId && conversations.some(c => c.id === pickedId)
      ? pickedId
      : conversations.at(-1)?.id ?? null;

  useStreamEvent("agent", e => {
    const known = conversations.some(c => c.id === e.conversation_id);
    if (known && (e.status !== "running" || e.step?.kind === "message")) threads.reload();
  });

  useStreamEvent("approval", () => {
    threads.reload();
  });

  const startConversation = async (message: string) => {
    const text = message.trim();
    if (!text || sending) return;
    setSending(true);
    setError(null);
    try {
      const { id } = await api.createConversation({
        title: `${site.name}：${text.slice(0, 28)}`,
        context: { nginx_site: site.name, file: site.file, managed: Boolean(site.managed) },
        message: text,
      });
      setPickedId(id);
      setDraftText("");
      threads.reload();
    } catch (e) {
      setError(toError(e));
    } finally {
      setSending(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void startConversation(draftText);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void startConversation(draftText);
    }
  };

  return (
    <div className={siteStyles.chatWrap}>
      <div className={siteStyles.chatTopBar}>
        <div className={siteStyles.chatQuick}>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            loading={sending}
            onClick={() => void startConversation("请全面检查这个站点的配置、证书状态、最近访问统计与错误日志，指出潜在问题并给出优化建议。")}
          >
            诊断此站点
          </Button>
          <Button
            type="button"
            size="sm"
            variant="secondary"
            loading={sending}
            onClick={() => void startConversation("请审查这个站点的安全与性能配置，撰写更优方案并通过变更申请提交，方便我核对 diff 后批准。")}
          >
            让代理优化配置
          </Button>
        </div>
        <div className={pageStyles.row}>
          {conversations.length > 1 && (
            <div className={siteStyles.threadPicker}>
              <Select
                label="历史对话"
                value={activeId ?? "__new"}
                onValueChange={v => setPickedId(v === "__new" ? "new" : v)}
                options={[
                  ...conversations.slice().reverse().map(c => ({
                    value: c.id,
                    label: `${c.title} · ${formatRelative(c.updated_at, now)}`,
                  })),
                  { value: "__new", label: "新对话" },
                ]}
              />
            </div>
          )}
          {activeId && (
            <>
              <Button type="button" size="sm" variant="ghost" onClick={() => setPickedId("new")}>新对话</Button>
              <Link className={`${pageStyles.small}`} to={`/agent/${activeId}`}>完整对话</Link>
            </>
          )}
        </div>
      </div>

      {error && <Alert tone="danger" title="发送失败" onDismiss={() => setError(null)}>{error}</Alert>}

      {activeId ? (
        <SiteConversationThread
          key={activeId}
          id={activeId}
          now={now}
          onReloadThreads={threads.reload}
          onApplied={onApplied}
        />
      ) : (
        <div className={pageStyles.stack}>
          <Alert tone="info" title={`围绕站点 ${site.name} 提问`}>
            代理会自动读取该站点的配置、证书与访问统计。你可以直接询问故障排查、日志异常，或让代理撰写配置变更并提交审批。
          </Alert>
          <form className={siteStyles.chatComposer} onSubmit={onSubmit}>
            <Textarea
              label="向代理提问"
              value={draftText}
              onChange={e => setDraftText(e.target.value)}
              onKeyDown={onKeyDown}
              rows={3}
              maxLength={8000}
              placeholder={`例如：为什么 ${site.name} 最近 5xx 偏高？或帮我加一个限流和 /api/ 反代规则`}
              description="Ctrl/⌘ + Enter 发送。代理只读查询并通过变更申请提交改动，批准后才会写入服务器。"
            />
            <div className={agentStyles.composerActions}>
              <Button type="submit" size="sm" loading={sending} disabled={!draftText.trim()}>发送给代理</Button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}

function SiteConversationThread({ id, now, onReloadThreads, onApplied }: {
  id: string;
  now: number;
  onReloadThreads: () => void;
  onApplied?: () => void;
}) {
  const detail = useQuery(() => api.conversation(id), [id]);
  const [streams, setStreams] = useState<Record<string, string>>({});
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bottom = useRef<HTMLDivElement>(null);

  useStreamEvent("agent", event => {
    if (event.conversation_id !== id) return;
    const known = detail.data?.runs.some(r => r.id === event.run_id);
    if (!known || event.status !== "running") {
      detail.reload();
      if (event.status !== "running") setStreams(s => omitKey(s, event.run_id));
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
    if (step.kind === "message") setStreams(s => omitKey(s, event.run_id));
  });

  useStreamEvent("approval", () => {
    if (detail.data?.requests?.length || detail.data?.runs.some(r => r.status === "running")) {
      detail.reload();
    }
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

  const send = async (e?: FormEvent) => {
    e?.preventDefault();
    const val = text.trim();
    if (!val || running || sending) return;
    setSending(true);
    setError(null);
    try {
      await api.sendMessage(id, val);
      setText("");
      detail.reload();
      onReloadThreads();
    } catch (err) {
      setError(toError(err));
    } finally {
      setSending(false);
    }
  };

  const cancel = async () => {
    if (!running) return;
    try {
      await api.cancelRun(running.id);
    } catch (err) {
      setError(toError(err));
    }
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      void send();
    }
  };

  return (
    <QueryView query={detail} skeletonLines={6} errorTitle="对话加载失败">
      {data => (
        <div className={pageStyles.stack}>
          <div className={siteStyles.chatThread} aria-live="polite">
            {data.runs.length === 0 && (
              <p className={pageStyles.textSecondary}>{data.queued ? "排队中，前面的对话完成后自动开始。" : "还没有消息。"}</p>
            )}
            {data.runs.map(run => <RunBlock key={run.id} run={run} stream={streams[run.id]} now={now} />)}
            <div ref={bottom} />
          </div>

          {data.requests && data.requests.length > 0 && (
            <section className={pageStyles.stack} aria-label="站点变更申请">
              <h3 className={siteStyles.groupTitle}>变更申请（可直接预览并审批）</h3>
              <ul className={pageStyles.list}>
                {data.requests.map(r => (
                  <li key={r.id}>
                    <ChangeRequestCard
                      request={r}
                      onChanged={next => {
                        detail.reload();
                        onReloadThreads();
                        if (next.status === "executed") onApplied?.();
                      }}
                      showLink={false}
                    />
                  </li>
                ))}
              </ul>
            </section>
          )}

          {error && <Alert tone="danger" title="发送失败" onDismiss={() => setError(null)}>{error}</Alert>}

          <form className={siteStyles.chatComposer} onSubmit={send}>
            <Textarea
              label="继续提问"
              value={text}
              onChange={e => setText(e.target.value)}
              onKeyDown={onKeyDown}
              rows={2}
              maxLength={8000}
              placeholder="继续追问或要求修改配置，例如：把限流改成每秒 30 次"
              description="Ctrl/⌘ + Enter 发送"
            />
            <div className={agentStyles.composerActions}>
              {running && <Button type="button" size="sm" variant="ghost" onClick={cancel}>停止</Button>}
              <Button type="submit" size="sm" loading={sending} disabled={Boolean(running) || !text.trim()}>发送</Button>
            </div>
          </form>
        </div>
      )}
    </QueryView>
  );
}

type ToolPair = { type: "tool"; call: AgentStep; result: AgentStep | null };
type Item = { type: "step"; step: AgentStep } | ToolPair;

function groupSteps(steps: AgentStep[]): Item[] {
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
    <section className={agentStyles.run} aria-label={chat ? "对话轮次" : "任务运行"}>
      {!chat && (
        <div className={agentStyles.runHeader}>
          <span className={pageStyles.row}>
            <Badge size="sm">{lookup(taskKindLabel, run.kind)}</Badge>
            <Badge size="sm" tone={runStatusTone[run.status]} dot>{runStatusLabel[run.status]}</Badge>
            <span className={`${pageStyles.muted} ${pageStyles.small}`}>
              {formatDateTime(run.started_at)} · {formatElapsed(run.started_at, run.finished_at, now)}
            </span>
          </span>
        </div>
      )}
      {groupSteps(run.steps).map(item => item.type === "tool"
        ? <ToolItem key={item.call.seq} call={item.call} result={item.result} />
        : <StepItem key={item.step.seq} step={item.step} chat={chat} />)}
      {run.status === "running" && (
        <div className={agentStyles.assistant}>
          {stream ? <p className={agentStyles.bubbleText}>{stream}</p> : <p className={`${pageStyles.muted} ${pageStyles.small}`}>代理正在分析…</p>}
        </div>
      )}
      {run.status === "cancelled" && <p className={`${pageStyles.muted} ${pageStyles.small}`}>已停止</p>}
    </section>
  );
}

function StepItem({ step, chat }: { step: AgentStep; chat: boolean }) {
  if (step.kind === "user") {
    return <div className={agentStyles.user}><p className={agentStyles.bubbleText}>{step.text}</p></div>;
  }
  if (step.kind === "error") {
    return <Alert tone="danger" title="运行出错">{step.text}</Alert>;
  }
  return (
    <div className={chat ? agentStyles.assistant : agentStyles.note}>
      <p className={agentStyles.bubbleText}>{step.text}</p>
    </div>
  );
}

function ToolItem({ call, result }: { call: AgentStep; result: AgentStep | null }) {
  const failed = Boolean(result?.output && typeof result.output === "object" && "error" in (result.output as object));
  return (
    <details className={agentStyles.tool}>
      <summary>
        <span className={pageStyles.row}>
          <code className={pageStyles.code}>{call.tool}</code>
          {result ? <Badge size="sm" tone={failed ? "danger" : "success"}>{failed ? "失败" : "完成"}</Badge> : <Badge size="sm" tone="info">执行中</Badge>}
        </span>
      </summary>
      <div className={pageStyles.stack}>
        {call.input !== null && call.input !== undefined && <JsonViewer data={call.input} rootName="input" defaultExpandDepth={2} maxHeight={220} label={`${call.tool ?? "工具"} 输入`} />}
        {result && <JsonViewer data={result.output} rootName="output" defaultExpandDepth={1} maxHeight={260} label={`${call.tool ?? "工具"} 输出`} />}
      </div>
    </details>
  );
}

function omitKey<T>(record: Record<string, T>, key: string): Record<string, T> {
  if (!(key in record)) return record;
  const next = { ...record };
  delete next[key];
  return next;
}
