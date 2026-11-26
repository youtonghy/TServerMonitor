import { useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { api } from "@/api/client";
import type { FirewallRule, FirewallStatus, NewFirewallRule, OpsJob } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { JobResult, OpsNotice, can, useOpsAction, useOpsCaps } from "@/components/ops";
import { Facts, PageHeader, Panel, Section } from "@/components/panel";
import opsStyles from "@/components/ops.module.css";
import styles from "./pages.module.css";
import local from "./settings.module.css";

const ACTION_LABEL: Record<string, string> = { allow: "放行", limit: "限速放行", deny: "拒绝", reject: "拒绝并回应", drop: "丢弃", accept: "放行", rich: "富规则" };
const ACTION_TONE: Record<string, "success" | "danger" | "warning" | "neutral"> = { allow: "success", accept: "success", limit: "warning", deny: "danger", reject: "danger", drop: "danger" };

type Row = FirewallRule & Record<string, unknown>;

export default function FirewallPage() {
  const caps = useOpsCaps();
  const status = useQuery(() => api.opsRead<FirewallStatus>("firewall.status"), []);
  const access = useQuery(() => api.access(60), []);
  const ops = useOpsAction();
  const [adding, setAdding] = useState<NewFirewallRule | null>(null);
  const [deleting, setDeleting] = useState<FirewallRule | null>(null);
  const [toggling, setToggling] = useState(false);

  const c = caps.data;
  const st = status.data?.data;
  const writable = Boolean(st?.writable);
  const allowAdd = can(c, "firewall", "add_rule") && writable;
  const allowDelete = can(c, "firewall", "delete_rule") && writable;
  const allowToggle = can(c, "firewall", "toggle") && st?.backend === "ufw";

  const done = async (p: Promise<OpsJob | null>) => {
    const j = await p;
    status.reload();
    return j?.status === "succeeded";
  };

  const columns: DataColumn<Row>[] = [
    { key: "action", label: "动作", sortable: true, render: (_v, r) => <Badge size="sm" tone={ACTION_TONE[r.action] ?? "neutral"}>{ACTION_LABEL[r.action] ?? r.action}</Badge> },
    { key: "port", label: "端口", sortable: true, render: (_v, r) => <code className={styles.code}>{r.port ?? "全部"}{r.proto ? `/${r.proto}` : ""}</code> },
    { key: "from", label: "来源", render: (_v, r) => <span className={styles.small}>{r.from ?? "任意地址"}</span> },
    { key: "spec", label: "规则", render: (_v, r) => <code className={`${styles.code} ${styles.muted}`}>{r.spec}</code> },
    { key: "deletable", label: "", render: (_v, r) => allowDelete && r.deletable ? <Button size="sm" variant="ghost" onClick={() => setDeleting(r)}>删除</Button> : null },
  ];

  const suspicious = access.data?.stats.suspicious ?? [];

  return (
    <>
      <PageHeader title="防火墙" description="ufw / firewalld 规则管理；每次修改都需在倒计时内确认，否则自动回滚">
        {allowToggle && st && <Button variant={st.active ? "secondary" : "primary"} onClick={() => setToggling(true)}>{st.active ? "停用 ufw" : "启用 ufw"}</Button>}
        {allowAdd && <Button onClick={() => setAdding({ action: "allow", port: "", proto: "tcp", from: "" })}>添加规则</Button>}
      </PageHeader>

      <OpsNotice caps={c} domain="firewall" />
      {ops.error && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}
      {ops.job && <Panel title="最近一次操作"><JobResult job={ops.job} onDismiss={() => ops.setJob(null)} /></Panel>}

      <Section title="状态" query={status} errorTitle="无法读取防火墙">
        {d => (
          <div className={styles.stack}>
            <Facts items={[
              { label: "后端", value: d.data.backend },
              { label: "状态", value: <Badge size="sm" tone={d.data.active ? "success" : "warning"} dot>{d.data.active ? "已启用" : "未启用"}</Badge> },
              { label: "默认入站", value: d.data.default_incoming ?? "—" },
              { label: "SSH 端口", value: d.data.ssh_ports.join(", ") },
              ...(d.data.zone ? [{ label: "区域", value: d.data.zone }] : []),
            ]} />
            {d.data.notes.map(n => <Alert key={n} tone="info" title="注意">{n}</Alert>)}
          </div>
        )}
      </Section>

      <Section
        title="规则"
        description="删除时按列出的规则原样删除；放行 SSH 的最后一条规则不能删除"
        query={status}
        flush
        isEmpty={d => d.data.rules.length === 0}
        empty={{ title: "没有规则", description: writable ? "还没有用户规则。" : "此后端仅支持查看，请参考下方原始规则。" }}
      >
        {d => <SortableDataTable<Row> rows={d.data.rules as Row[]} columns={columns} rowKey="spec" caption="防火墙规则" />}
      </Section>

      {suspicious.length > 0 && (
        <Panel title="可疑来源" description="最近一小时访问日志中扫描敏感路径或大量 4xx 的地址">
          <ul className={styles.list}>
            {suspicious.map(s => (
              <li key={s.ip} className={local.providerRow}>
                <div className={local.providerMain}>
                  <code className={styles.code}>{s.ip}</code>
                  <span className={`${styles.small} ${styles.muted}`}>{s.requests} 个请求 · {s.s4xx ?? 0} 个 4xx · {s.scan ?? 0} 次扫描路径</span>
                </div>
                {allowAdd && <Button size="sm" variant="secondary" onClick={() => setAdding({ action: "deny", port: "1-65535", proto: "tcp", from: s.ip })}>封禁</Button>}
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {st?.raw && (
        <Panel title="原始规则" description={`${st.backend} 的当前输出`}>
          <CodeBlock code={st.raw} language="log" filename={`${st.backend}.txt`} maxLines={16} />
        </Panel>
      )}

      <RuleDialog rule={adding} onClose={() => setAdding(null)} onSubmit={r => done(ops.run("firewall.add", { ...r, from: r.from || null }))} />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={o => { if (!o) setDeleting(null); }}
        title="删除这条规则？"
        description="删除后需在倒计时内确认，否则自动恢复。"
        danger
        confirmLabel="删除"
        onConfirm={async () => { if (deleting) await done(ops.run("firewall.delete", { spec: deleting.spec })); }}
      >
        <code className={styles.code}>{deleting?.spec}</code>
      </ConfirmDialog>
      <ConfirmDialog
        open={toggling}
        onOpenChange={setToggling}
        title={st?.active ? "停用 ufw？" : "启用 ufw？"}
        description={st?.active ? "停用后所有入站端口都将对外开放。" : "启用前必须已有放行 SSH 的规则。"}
        danger={st?.active}
        requireText={st?.active ? "ufw" : undefined}
        onConfirm={() => done(ops.run("firewall.toggle", { enabled: !st?.active }))}
      />
    </>
  );
}

function RuleDialog({ rule, onClose, onSubmit }: { rule: NewFirewallRule | null; onClose: () => void; onSubmit: (r: NewFirewallRule) => Promise<boolean> }) {
  const [draft, setDraft] = useState<NewFirewallRule | null>(rule);
  const [busy, setBusy] = useState(false);
  const [lastRule, setLastRule] = useState(rule);
  if (rule !== lastRule) {
    setLastRule(rule);
    setDraft(rule);
  }
  const set = <K extends keyof NewFirewallRule>(k: K, v: NewFirewallRule[K]) => setDraft(d => d && { ...d, [k]: v });
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!draft) return;
    setBusy(true);
    try {
      // stays open on refusal (e.g. missing ops token) so the draft is not lost
      if (await onSubmit(draft)) onClose();
    } finally {
      setBusy(false);
    }
  };
  const blocksAll = draft && (draft.action === "deny" || draft.action === "reject") && !draft.from;
  return (
    <Dialog open={rule !== null} onOpenChange={o => { if (!o) onClose(); }}>
      <DialogContent title="添加防火墙规则" description="规则立即生效，需在倒计时内确认，否则自动回滚。">
        {draft && (
          <form className={local.form} onSubmit={submit}>
            <Select label="动作" value={draft.action} onValueChange={v => set("action", v as NewFirewallRule["action"])} options={[
              { value: "allow", label: "放行" }, { value: "deny", label: "拒绝" }, { value: "reject", label: "拒绝并回应" }, { value: "limit", label: "限速放行（仅 ufw）" },
            ]} />
            <Input label="端口" value={draft.port} onChange={e => set("port", e.target.value)} description="单个端口或范围，如 443 或 8000-8100" required maxLength={11} pattern="\d{1,5}([:\-]\d{1,5})?" />
            <Select label="协议" value={draft.proto} onValueChange={v => set("proto", v as NewFirewallRule["proto"])} options={[{ value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }, { value: "any", label: "TCP 和 UDP" }]} />
            <Input label="来源地址" value={draft.from ?? ""} onChange={e => set("from", e.target.value)} description="IP 或 CIDR，如 203.0.113.7 或 10.0.0.0/8；留空表示任意地址" maxLength={64} />
            {blocksAll && <p className={opsStyles.muted}>对任意来源拒绝 SSH 端口的规则会被拒绝执行。</p>}
            <div className={local.actions}>
              <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
              <Button type="submit" loading={busy}>添加</Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
