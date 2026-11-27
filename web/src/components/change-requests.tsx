import { useEffect, useState } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge, type BadgeTone } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { Input } from "@/components/arc/input/input";
import { JsonViewer } from "@/components/arc/json-viewer/json-viewer";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { ChangeRequest, ChangeRequestStatus } from "@/api/types";
import { formatDateTime } from "@/lib/format";
import { Link, navigate, useRoute } from "@/lib/router";
import { ConfirmDialog } from "./confirm-dialog";
import { errorMessage } from "./panel";
import styles from "./ops.module.css";
import page from "@/pages/pages.module.css";

const requestStatusLabel: Record<ChangeRequestStatus, string> = {
  pending: "待批准", approved: "执行中", rejected: "已拒绝", expired: "已过期", executed: "已执行", failed: "失败",
};
const requestStatusTone: Record<ChangeRequestStatus, BadgeTone> = {
  pending: "warning", approved: "info", rejected: "neutral", expired: "neutral", executed: "success", failed: "danger",
};

function toError(e: unknown): string {
  return errorMessage(e instanceof Error ? e : new Error(String(e)));
}

/** Number of change requests waiting for a person; follows the `approval` event. */
export function usePendingApprovals(): number {
  const [count, setCount] = useState(0);
  const load = () => api.approvals("open", 1).then(r => setCount(r.pending)).catch(() => undefined);
  useEffect(() => {
    void load();
  }, []);
  useStreamEvent("approval", () => void load());
  return count;
}

/** Pinned above every page while agents wait for a decision (hidden on the approvals page itself). */
export function ApprovalBanner({ count }: { count: number }) {
  const route = useRoute();
  if (!count || route.segments[0] === "approvals") return null;
  return (
    <div className={styles.banner} role="region" aria-label="待批准的变更申请">
      <div className={styles.bannerRow}>
        <div className={styles.bannerText}>
          <span className={styles.bannerTitle}>{count} 个 Agent 变更申请等待批准</span>
          <span className={styles.bannerHint}>批准前请核对调用理由、参数和预演结果；不处理的申请 30 分钟后自动过期。</span>
        </div>
        <div className={styles.bannerActions}>
          <Button size="sm" onClick={() => navigate("/approvals")}>去审批</Button>
        </div>
      </div>
    </div>
  );
}

function sourceLabel(r: ChangeRequest): string {
  if (r.source === "agent") return "内置 Agent";
  if (r.source === "mcp") return `外部 Agent（MCP${r.actor ? ` · ${r.actor}` : ""}）`;
  return r.source;
}

/** Diff (nginx file, sshd options) or plan from the dry run. */
function PreviewView({ preview }: { preview: NonNullable<ChangeRequest["preview"]> }) {
  const diff = preview.result?.diff;
  if (typeof diff === "string") return <CodeBlock code={diff} language="diff" filename="预演 diff" maxLines={24} />;
  if (preview.log) return <CodeBlock code={preview.log} language="log" filename="预演输出" maxLines={14} />;
  if (preview.result) return <JsonViewer data={preview.result} rootName="preview" defaultExpandDepth={2} maxHeight={240} label="预演结果" />;
  return <p className={styles.muted}>预演没有输出。</p>;
}

/** One change request: what, why, who, the dry run, and approve / reject while pending. */
export function ChangeRequestCard({ request, onChanged, showLink = true }: {
  request: ChangeRequest;
  onChanged?: (next: ChangeRequest) => void;
  /** Link to the conversation that filed it. */
  showLink?: boolean;
}) {
  const [confirming, setConfirming] = useState<"approve" | "reject" | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const r = request;
  const pending = r.status === "pending";

  const decide = async (what: "approve" | "reject") => {
    setError(null);
    try {
      const next = what === "approve" ? await api.approve(r.id) : await api.reject(r.id, note);
      onChanged?.(next);
    } catch (e) {
      setError(toError(e));
      throw e;
    }
  };

  return (
    <article className={page.stack} aria-label={`变更申请 #${r.id}`}>
      <div className={page.between}>
        <p className={page.itemTitle}>#{r.id} {r.summary}</p>
        <span className={page.row}>
          <Badge size="sm" outline>{r.kind === "host" ? "服务器" : "面板"}</Badge>
          {r.mode === "auto" && <Badge size="sm" tone="neutral">自动放行</Badge>}
          <Badge size="sm" tone={requestStatusTone[r.status]} dot>{requestStatusLabel[r.status]}</Badge>
        </span>
      </div>
      <p className={page.text}><span className={page.muted}>调用理由：</span>{r.reason}</p>
      <p className={`${page.muted} ${page.small}`}>
        {r.label}（<code className={page.code}>{r.action}</code>）· {sourceLabel(r)} · {formatDateTime(r.created_at)}
        {pending && <> · {formatDateTime(r.expires_at)} 过期</>}
        {r.decided_by && r.decided_by !== "auto" && <> · {r.status === "rejected" ? "拒绝" : "批准"}人 {r.decided_by}</>}
        {showLink && r.conversation_id && <> · <Link to={`/agent/${r.conversation_id}`}>查看对话</Link></>}
      </p>
      <details>
        <summary className={page.small}>调用参数</summary>
        <JsonViewer data={r.args} rootName="args" defaultExpandDepth={2} maxHeight={240} label="调用参数" />
      </details>
      {r.preview && <PreviewView preview={r.preview} />}
      {r.note && <p className={page.textSecondary}>批准人备注：{r.note}</p>}
      {r.error && <Alert tone="danger" title="执行失败">{r.error}</Alert>}
      {r.status === "executed" && r.result != null && (
        <details>
          <summary className={page.small}>执行结果{r.job_id ? <> · <Link to="/ops">运维记录 #{r.job_id}</Link></> : null}</summary>
          <JsonViewer data={r.result} rootName="result" defaultExpandDepth={1} maxHeight={240} label="执行结果" />
        </details>
      )}
      {error && <Alert tone="danger" title="操作失败" onDismiss={() => setError(null)}>{error}</Alert>}
      {pending && (
        <div className={styles.confirmActions}>
          <Button size="sm" variant="secondary" onClick={() => { setNote(""); setConfirming("reject"); }}>拒绝</Button>
          <Button size="sm" onClick={() => setConfirming("approve")}>批准并执行</Button>
        </div>
      )}
      <ConfirmDialog
        open={confirming === "approve"}
        onOpenChange={open => { if (!open) setConfirming(null); }}
        title="批准并执行这项变更？"
        description={r.summary}
        confirmLabel="批准并执行"
        danger={r.kind === "host"}
        wide
        onConfirm={() => decide("approve")}
      >
        <p className={styles.muted}>理由：{r.reason}</p>
        {r.preview && <PreviewView preview={r.preview} />}
        <p className={styles.muted}>执行时按上面的参数运行，结果会记录在运维记录{r.source === "agent" ? "，并回报给发起的对话" : ""}。防火墙和 SSH 变更仍需在执行后另行确认。</p>
      </ConfirmDialog>
      <ConfirmDialog
        open={confirming === "reject"}
        onOpenChange={open => { if (!open) setConfirming(null); }}
        title="拒绝这项变更？"
        description={r.summary}
        confirmLabel="拒绝"
        onConfirm={() => decide("reject")}
      >
        <Input label="备注（可选，发起的 Agent 会看到）" value={note} onChange={e => setNote(e.target.value)} maxLength={500} />
      </ConfirmDialog>
    </article>
  );
}
