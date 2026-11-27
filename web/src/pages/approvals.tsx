import { useState } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { Switch } from "@/components/arc/switch/switch";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { ApprovalPolicy, ChangeRequest } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ChangeRequestCard } from "@/components/change-requests";
import { PageHeader, Panel, Section, errorMessage } from "@/components/panel";
import styles from "./pages.module.css";

type Tab = "open" | "all" | "policy";
const TABS: { value: Tab; label: string }[] = [
  { value: "open", label: "待批准" },
  { value: "all", label: "全部记录" },
  { value: "policy", label: "批准策略" },
];

export default function ApprovalsPage() {
  const [tab, setTab] = useState<Tab>("open");
  return (
    <>
      <PageHeader title="变更审批" description="内置 Agent 和外部 Agent（MCP）提交的变更申请：核对理由、参数和预演结果后批准或拒绝">
        <SegmentedControl label="视图" options={TABS} value={tab} onValueChange={v => setTab(v as Tab)} />
      </PageHeader>
      {tab === "policy" ? <PolicyPanel /> : <RequestList key={tab} status={tab} />}
    </>
  );
}

function RequestList({ status }: { status: "open" | "all" }) {
  const list = useQuery(() => api.approvals(status, 100), [status]);
  useStreamEvent("approval", () => list.reload());
  const replace = (next: ChangeRequest) =>
    list.setData(prev => prev && { ...prev, requests: prev.requests.map(r => (r.id === next.id ? next : r)) });
  return (
    <Section
      title={status === "open" ? "等待批准" : "全部申请"}
      query={list}
      skeletonLines={6}
      isEmpty={data => data.requests.length === 0}
      empty={status === "open"
        ? { title: "没有待批准的申请", description: "Agent 提交需要人工批准的变更时会出现在这里。" }
        : { title: "还没有变更申请", description: "Agent 通过 propose_change 或 MCP 写工具提交的申请会记录在这里。" }}
    >
      {data => (
        <ul className={styles.list}>
          {data.requests.map(r => <li key={r.id}><ChangeRequestCard request={r} onChanged={replace} /></li>)}
        </ul>
      )}
    </Section>
  );
}

const KIND_TITLE = { host: "服务器变更", panel: "面板操作" } as const;

function PolicyPanel() {
  const policy = useQuery(() => api.approvalPolicy(), []);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const toggle = async (p: ApprovalPolicy, needsApproval: boolean) => {
    setBusy(p.action);
    setError(null);
    try {
      const next = await api.setApprovalPolicy(p.action, needsApproval ? "approve" : "auto");
      policy.setData(() => next);
    } catch (e) {
      setError(errorMessage(e instanceof Error ? e : new Error(String(e))));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className={styles.stack}>
      <Alert tone="info" title="自动放行的操作仍会记录">
        需人工批准的操作，会先做一次预演（服务器变更），等你在本页批准后才执行。关闭开关的操作会在 Agent 提交时立即执行，并记录在全部记录和运维记录里。修改策略需要先确认密码。账号、API 令牌和密钥类设置不对 Agent 开放。
      </Alert>
      {error && <Alert tone="danger" title="无法修改策略" onDismiss={() => setError(null)}>{error}</Alert>}
      <Section title="批准策略" query={policy} skeletonLines={8}>
        {data => (
          <div className={styles.stack}>
            {(["host", "panel"] as const).map(kind => (
              <Panel key={kind} title={KIND_TITLE[kind]}>
                <ul className={styles.list}>
                  {data.filter(p => p.kind === kind).map(p => (
                    <li key={p.action}>
                      <div className={styles.between}>
                        <div>
                          <p className={styles.itemTitle}>{p.label}</p>
                          <p className={styles.textSecondary}>
                            <code className={styles.code}>{p.action}</code>
                            {p.mode !== p.default && <> · 已修改（默认{p.default === "approve" ? "需批准" : "自动放行"}）</>}
                            {!p.agent && <> · 仅外部 Agent</>}
                          </p>
                        </div>
                        <span className={styles.row}>
                          {p.mode === "auto" && <Badge size="sm" tone="warning">自动放行</Badge>}
                          <Switch
                            label="需人工批准"
                            checked={p.mode === "approve"}
                            disabled={busy === p.action}
                            onCheckedChange={v => void toggle(p, v)}
                          />
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              </Panel>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}
