// Shared pieces of the management pages: capability checks, the read-only notice, and a hook
// that runs one helper call and keeps its job, error and busy state.
import { useCallback, useState } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { api } from "@/api/client";
import type { OpsCapabilities, OpsDomain, OpsJob } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { errorMessage } from "./panel";
import styles from "./ops.module.css";

export const DOMAIN_LABEL: Record<OpsDomain, string> = { docker: "Docker", nginx: "nginx", firewall: "防火墙", ssh: "SSH" };

export function useOpsCaps() {
  return useQuery(() => api.opsCapabilities(), []);
}

/** True when `op` may be run in `domain` right now. */
export function can(caps: OpsCapabilities | undefined, domain: OpsDomain, op: string): boolean {
  const d = caps?.domains[domain];
  return Boolean(caps?.write_ready && d?.enabled && d.allow.includes(op));
}

/** Explains why a management page is read-only (or that the helper is in dry-run mode). */
export function OpsNotice({ caps, domain, source }: { caps: OpsCapabilities | undefined; domain: OpsDomain; source?: "helper" | "local" }) {
  if (!caps) return null;
  const d = caps.domains[domain];
  if (!caps.available) {
    return (
      <Alert tone="info" title="只读模式">
        {caps.reason}。{source === "local" ? "下面显示的是守护进程自己能看到的内容。" : ""}如需在这里管理{DOMAIN_LABEL[domain]}，请按 deploy/tsmonitor-helper.service 中的说明安装运维助手并在 helper.toml 中开启 [{domain}]。
      </Alert>
    );
  }
  if (!d?.enabled) {
    return <Alert tone="info" title="只读模式">运维助手已运行，但没有开启 {DOMAIN_LABEL[domain]} 管理（helper.toml 中 [{domain}] enabled = false）。</Alert>;
  }
  if (!caps.write_ready) return <Alert tone="info" title="只读模式">{caps.write_reason}</Alert>;
  return (
    <>
      {caps.dry_run && <Alert tone="warning" title="演练模式">运维助手设置了 dry_run = true：所有操作只记录将要执行的命令，不会真正修改服务器。</Alert>}
      {d.allow.length === 0 && <Alert tone="info" title="只读模式">{DOMAIN_LABEL[domain]} 已开启查看，但 helper.toml 的 allow 列表为空，没有允许任何修改。</Alert>}
    </>
  );
}

export const JOB_TONE = { running: "info", succeeded: "success", failed: "danger", unknown: "warning" } as const;
export const JOB_LABEL = { running: "进行中", succeeded: "完成", failed: "失败", unknown: "状态未知" } as const;

/** Runs helper calls for one page. `run` resolves to the job (also when it failed) or null on refusal. */
export function useOpsAction() {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [job, setJob] = useState<OpsJob | null>(null);
  const run = useCallback(async (call: string, args: Record<string, unknown> = {}, dryRun = false): Promise<OpsJob | null> => {
    setBusy(call);
    setError(null);
    try {
      const j = await api.opsRun(call, args, dryRun);
      setJob(j);
      if (j.status === "failed") setError(j.error ?? "操作失败");
      return j;
    } catch (e) {
      setError(errorMessage(e instanceof Error ? e : new Error(String(e))));
      return null;
    } finally {
      setBusy(null);
    }
  }, []);
  return { run, busy, error, setError, job, setJob };
}

/** Outcome of the last job on a page: status, error and log. */
export function JobResult({ job, onDismiss }: { job: OpsJob; onDismiss?: () => void }) {
  const text = job.log ?? "";
  return (
    <div className={styles.result}>
      <div className={styles.resultHead}>
        <Badge size="sm" tone={JOB_TONE[job.status]} dot>{JOB_LABEL[job.status]}</Badge>
        {job.dry_run && <Badge size="sm" tone="neutral" outline>演练</Badge>}
        <span className={styles.resultTitle}>{job.summary}</span>
        {onDismiss && <button type="button" className={styles.linkButton} onClick={onDismiss}>收起</button>}
      </div>
      {job.status === "running" && <p className={styles.muted}>仍在执行，可在「运维记录」中查看实时输出。</p>}
      {text && <CodeBlock code={text} language="log" filename={`ops-job-${job.id}.log`} maxLines={14} />}
    </div>
  );
}

/** Unified diff returned by a dry run, if any. */
export function diffOf(job: OpsJob | null): string | null {
  const d = job?.result?.diff;
  return typeof d === "string" ? d : null;
}
