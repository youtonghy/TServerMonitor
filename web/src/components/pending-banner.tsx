import { useEffect, useState } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Button } from "@/components/arc/button/button";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { PendingChange } from "@/api/types";
import { errorMessage } from "./panel";
import { ConfirmDialog } from "./confirm-dialog";
import styles from "./ops.module.css";

const DOMAIN: Record<string, string> = { firewall: "防火墙", ssh: "SSH" };

function left(deadline: number, now: number): string {
  const s = Math.max(0, Math.round((deadline - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/** Firewall / sshd changes waiting for a person to confirm them; they revert at the deadline. */
export function PendingBanner() {
  const [items, setItems] = useState<PendingChange[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const [confirming, setConfirming] = useState<PendingChange | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = () => api.opsPending().then(setItems).catch(() => undefined);
  useEffect(() => {
    void load();
  }, []);
  useStreamEvent("ops_pending", setItems);
  useEffect(() => {
    if (!items.length) return;
    const t = setInterval(() => {
      const n = Date.now();
      setNow(n);
      // the helper reverts on its own timer; refresh shortly after a deadline passes
      if (items.some(p => p.deadline < n - 2000)) void load();
    }, 1000);
    return () => clearInterval(t);
  }, [items]);

  if (!items.length) return null;

  const act = async (p: PendingChange, call: "pending.confirm" | "pending.revert") => {
    setBusy(p.id);
    setError(null);
    try {
      const j = await api.opsRun(call, { id: p.id });
      if (j.status === "failed") setError(j.error ?? "操作失败");
      await load();
    } catch (e) {
      setError(errorMessage(e instanceof Error ? e : new Error(String(e))));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className={styles.banner} role="region" aria-label="待确认的变更">
      {error && <Alert tone="danger" title="操作失败" onDismiss={() => setError(null)}>{error}</Alert>}
      {items.map(p => (
        <div key={p.id} className={styles.bannerRow}>
          <div className={styles.bannerText}>
            <span className={styles.bannerTitle}>待确认的{DOMAIN[p.domain] ?? p.domain}变更：{p.summary}</span>
            <span className={styles.bannerHint}>
              <span className={styles.countdown}>{left(p.deadline, now)}</span> 后自动回滚{p.via === "mcp" ? " · 由外部 Agent 发起" : p.via === "agent" ? " · 由内置 Agent 发起（已批准）" : ""}。确认前请新开一个 SSH 会话，确认仍能登录。
            </span>
          </div>
          <div className={styles.bannerActions}>
            <Button size="sm" variant="secondary" loading={busy === p.id} onClick={() => act(p, "pending.revert")}>立即撤销</Button>
            <Button size="sm" onClick={() => setConfirming(p)} disabled={busy === p.id}>保留变更</Button>
          </div>
        </div>
      ))}
      <ConfirmDialog
        open={confirming !== null}
        onOpenChange={open => { if (!open) setConfirming(null); }}
        title="保留这项变更？"
        description={confirming?.summary}
        confirmLabel="我已用新会话登录成功，保留"
        onConfirm={async () => { if (confirming) await act(confirming, "pending.confirm"); }}
      >
        <p className={styles.muted}>已经建立的 SSH 连接不受防火墙和 sshd 重载影响，所以"当前还连着"不能证明新登录可用。请先在另一个终端新建连接并登录成功，再保留变更。</p>
      </ConfirmDialog>
    </div>
  );
}
