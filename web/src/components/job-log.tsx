import { useState } from "react";
import { Badge } from "@/components/arc/badge/badge";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import { useQuery } from "@/api/useQuery";
import { formatDateTime } from "@/lib/format";
import { JOB_LABEL, JOB_TONE } from "./ops";
import { Panel } from "./panel";
import styles from "./ops.module.css";

/** Log of one ops job: the stored log plus lines streamed while it runs. */
export function OpsJobLog({ id }: { id: number }) {
  const job = useQuery(() => api.opsJob(id), [id]);
  const [live, setLive] = useState("");
  useStreamEvent("ops_job", e => {
    if (e.id !== id) return;
    if (e.line !== null) setLive(l => l + e.line + "\n");
    if (e.status !== "running") {
      setLive("");
      job.reload();
    }
  });
  const j = job.data;
  const text = j?.status === "running" ? (j.log ?? "") + live : j?.log ?? live;
  return (
    <Panel
      title={j?.summary ?? "任务日志"}
      description={j ? `${formatDateTime(j.started_at)} · 来自 ${j.via === "mcp" ? "外部 Agent（MCP）" : "面板"}${j.remote ? ` · ${j.remote}` : ""}` : undefined}
      actions={j && <span className={styles.resultHead}>{j.dry_run && <Badge size="sm" tone="neutral" outline>演练</Badge>}<Badge size="sm" tone={JOB_TONE[j.status]} dot>{JOB_LABEL[j.status]}</Badge></span>}
    >
      {j?.error && <p className={styles.muted}>{j.error}</p>}
      {text ? <CodeBlock code={text} language="log" filename={`ops-job-${id}.log`} maxLines={30} /> : <p className={styles.muted}>{j?.status === "running" ? "等待输出…" : "没有输出"}</p>}
    </Panel>
  );
}
