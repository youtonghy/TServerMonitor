import { useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { Textarea } from "@/components/arc/textarea/textarea";
import { api } from "@/api/client";
import type { SshConfig, SshKey, SshKeys, SshSession } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { JobResult, OpsNotice, can, diffOf, useOpsAction, useOpsCaps } from "@/components/ops";
import { Facts, PageHeader, Panel, Section } from "@/components/panel";
import { findingSeverityLabel, findingSeverityTone } from "@/lib/labels";
import opsStyles from "@/components/ops.module.css";
import styles from "./pages.module.css";
import local from "./settings.module.css";

const OPTION_HINT: Record<string, string> = {
  PermitRootLogin: "root 登录方式",
  PasswordAuthentication: "密码登录",
  PubkeyAuthentication: "公钥登录",
  KbdInteractiveAuthentication: "键盘交互（含部分密码/二次验证）",
  PermitEmptyPasswords: "空密码",
  X11Forwarding: "X11 转发",
  AllowTcpForwarding: "TCP 转发",
  AllowAgentForwarding: "agent 转发",
  UseDNS: "反向解析客户端",
  MaxAuthTries: "单连接最多认证次数（1–10）",
  LoginGraceTime: "登录超时秒数（10–600）",
  ClientAliveInterval: "保活间隔秒数（0 = 关闭）",
  ClientAliveCountMax: "保活失败次数上限",
  MaxSessions: "单连接最多会话数",
  Port: "监听端口（需防火墙已放行）",
};

type KeyRow = SshKey & Record<string, unknown>;
type SessionRow = SshSession & { key: string } & Record<string, unknown>;

export default function SshPage() {
  const caps = useOpsCaps();
  const config = useQuery(() => api.opsRead<SshConfig>("ssh.config"), []);
  const keys = useQuery(() => api.opsRead<SshKeys>("ssh.keys"), []);
  const sessions = useQuery(() => api.sshSessions(), [], { refreshMs: 30_000 });
  const findings = useQuery(() => api.findings(), []);
  const ops = useOpsAction();
  const [changes, setChanges] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<SshKey | null>(null);

  const c = caps.data;
  const cfg = config.data?.data;
  const allowOptions = can(c, "ssh", "options") && Boolean(cfg?.available) && Boolean(cfg?.includes_dropins);
  const pending = Object.entries(changes).filter(([k, v]) => v !== "" && v !== current(cfg, k));

  const reviewOptions = async () => {
    const j = await ops.run("ssh.set", { options: Object.fromEntries(pending) }, true);
    if (j?.status === "succeeded") setPreview(diffOf(j) ?? "");
  };
  const applyOptions = async () => {
    const j = await ops.run("ssh.set", { options: Object.fromEntries(pending) });
    if (j?.status === "succeeded") {
      setChanges({});
      config.reload();
    }
  };

  const keyColumns: DataColumn<KeyRow>[] = [
    { key: "user", label: "用户", sortable: true, render: (_v, r) => <code className={styles.code}>{r.user}</code> },
    { key: "kind", label: "类型", sortable: true },
    { key: "fingerprint", label: "指纹", render: (_v, r) => <code className={`${styles.code} ${styles.small}`}>{r.fingerprint}</code> },
    { key: "comment", label: "备注", render: (_v, r) => <span className={styles.row}><span className={styles.small}>{r.comment || "—"}</span>{r.restricted && <Badge size="sm" tone="neutral" outline>有限制</Badge>}</span> },
    { key: "restricted", label: "", render: (_v, r) => can(c, "ssh", "key_remove") ? <Button size="sm" variant="ghost" onClick={() => setRemoving(r)}>删除</Button> : null },
  ];
  const sessionColumns: DataColumn<SessionRow>[] = [
    { key: "user", label: "用户", sortable: true },
    { key: "tty", label: "终端" },
    { key: "from", label: "来源", render: (_v, r) => <code className={styles.code}>{r.from ?? "本地"}</code> },
    { key: "since", label: "登录时间", sortable: true },
  ];
  const loginFindings = (findings.data ?? []).filter(f => f.category === "login" || f.title.includes("SSH"));

  return (
    <>
      <PageHeader title="SSH" description="sshd 设置、授权公钥与登录会话；sshd 修改需在倒计时内确认，否则自动回滚">
        {can(c, "ssh", "key_add") && <Button onClick={() => setAdding(true)}>添加公钥</Button>}
      </PageHeader>

      <OpsNotice caps={c} domain="ssh" source={config.data?.source} />
      {ops.error && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}
      {ops.job && !(ops.job.dry_run && diffOf(ops.job)) && <Panel title="最近一次操作"><JobResult job={ops.job} onDismiss={() => ops.setJob(null)} /></Panel>}

      <Section title="sshd" query={config} errorTitle="无法读取 sshd 配置">
        {d => (
          <div className={styles.stack}>
            <Facts items={[
              { label: "监听端口", value: d.data.ports.join(", ") },
              { label: "服务", value: d.data.unit ?? "—" },
              { label: "按需启动（ssh.socket）", value: d.data.socket_activated ? "是" : "否" },
              { label: "面板写入的文件", value: d.data.dropin ? <code className={styles.code}>{d.data.dropin}</code> : "—" },
            ]} />
            {!d.data.available && <Alert tone="info" title="仅显示配置文件">需要运维助手执行 sshd -T 才能看到生效值；当前只解析了 sshd_config 中的端口。</Alert>}
            {d.data.available && !d.data.includes_dropins && <Alert tone="warning" title="无法通过面板修改">sshd_config 没有在 Match 之前 Include sshd_config.d/*.conf，面板写入的设置不会生效。</Alert>}
          </div>
        )}
      </Section>

      {cfg?.available && (
        <Panel
          title="登录与安全选项"
          description="写入独立的 drop-in 文件；保存前执行 sshd -t 并核对生效值，会锁死登录的组合会被拒绝"
          actions={allowOptions && <Button size="sm" disabled={pending.length === 0} loading={ops.busy === "ssh.set"} onClick={reviewOptions}>预览并应用{pending.length ? `（${pending.length}）` : ""}</Button>}
        >
          <ul className={styles.list}>
            {cfg.options.map(o => {
              const cur = current(cfg, o.key);
              const managed = cfg.managed[o.key];
              return (
                <li key={o.key} className={local.providerRow}>
                  <div className={local.providerMain}>
                    <span className={styles.row}>
                      <code className={styles.code}>{o.key}</code>
                      {managed !== undefined && <Badge size="sm" tone="info" outline>面板设置</Badge>}
                    </span>
                    <span className={`${styles.small} ${styles.muted}`}>{OPTION_HINT[o.key] ?? ""} · 当前 {cur ?? "未知"}</span>
                  </div>
                  {allowOptions && (o.values.length > 0
                    ? <Select label={o.key} className={local.inlineSelect} value={changes[o.key] ?? cur ?? ""} onValueChange={v => setChanges(x => ({ ...x, [o.key]: v }))} options={o.values.map(v => ({ value: v, label: v }))} />
                    : <Input label={o.key} className={local.inlineSelect} inputMode="numeric" value={changes[o.key] ?? cur ?? ""} onChange={e => setChanges(x => ({ ...x, [o.key]: e.target.value.replace(/\D/g, "") }))} />)}
                </li>
              );
            })}
          </ul>
        </Panel>
      )}

      <Section
        title="授权公钥"
        description="各登录用户的 ~/.ssh/authorized_keys；带 from= / command= 等限制的条目只显示不修改"
        query={keys}
        flush
        isEmpty={d => d.data.keys.length === 0}
        empty={{ title: "没有公钥", description: "登录用户都还没有配置公钥。" }}
        errorTitle="无法读取公钥"
      >
        {d => <SortableDataTable<KeyRow> rows={d.data.keys as KeyRow[]} columns={keyColumns} rowKey={r => `${r.user}:${r.fingerprint}`} caption="授权公钥" />}
      </Section>

      <div className={styles.grid2}>
        <Section title="当前会话" query={sessions} flush isEmpty={d => d.length === 0} empty={{ title: "没有登录会话", description: "who 没有返回任何会话。" }}>
          {d => <SortableDataTable<SessionRow> rows={d.map((s, i) => ({ ...s, key: `${s.tty}:${i}` }))} columns={sessionColumns} rowKey="key" caption="登录会话" />}
        </Section>
        <Section title="登录安全" query={findings} isEmpty={() => loginFindings.length === 0} empty={{ title: "没有登录相关风险", description: "没有暴力破解或 root 登录记录。" }}>
          {() => (
            <ul className={styles.list}>
              {loginFindings.map(f => (
                <li key={f.id} className={local.providerMain}>
                  <span className={styles.row}><Badge size="sm" tone={findingSeverityTone[f.severity]}>{findingSeverityLabel[f.severity]}</Badge><span className={styles.strong}>{f.title}</span></span>
                  <p className={styles.textSecondary}>{f.detail}</p>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      <ConfirmDialog
        open={preview !== null}
        onOpenChange={o => { if (!o) setPreview(null); }}
        title="应用 sshd 设置？"
        description={`应用后需在 ${c?.confirm_secs ?? 120} 秒内用新会话登录并确认，否则自动回滚。`}
        confirmLabel="应用"
        wide
        onConfirm={applyOptions}
      >
        {preview ? <CodeBlock code={preview} language="diff" filename="sshd-dropin.diff" maxLines={20} /> : <p className={opsStyles.muted}>没有变化。</p>}
      </ConfirmDialog>
      <ConfirmDialog
        open={removing !== null}
        onOpenChange={o => { if (!o) setRemoving(null); }}
        title={`删除 ${removing?.user ?? ""} 的公钥？`}
        description="如果这是唯一可用的登录方式，删除会被拒绝。"
        danger
        confirmLabel="删除"
        onConfirm={async () => { if (removing) { await ops.run("ssh.key_remove", { user: removing.user, fingerprint: removing.fingerprint }); keys.reload(); } }}
      >
        <code className={styles.code}>{removing?.fingerprint}</code>
      </ConfirmDialog>
      <KeyDialog open={adding} onOpenChange={setAdding} users={keys.data?.data.users ?? []} onSubmit={async (user, key) => { const j = await ops.run("ssh.key_add", { user, key }); keys.reload(); return j?.status === "succeeded"; }} />
    </>
  );
}

function current(cfg: SshConfig | undefined, key: string): string | undefined {
  const v = cfg?.effective[key.toLowerCase()]?.[0];
  return v === "without-password" ? "prohibit-password" : v;
}

function KeyDialog({ open, onOpenChange, users, onSubmit }: { open: boolean; onOpenChange: (o: boolean) => void; users: string[]; onSubmit: (user: string, key: string) => Promise<boolean> }) {
  const [user, setUser] = useState("");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      if (await onSubmit(user || users[0], key)) {
        setKey("");
        onOpenChange(false);
      }
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="添加 SSH 公钥" description="只接受一行公钥（ssh-ed25519、ssh-rsa、ecdsa…），不能带选项。">
        <form className={local.form} onSubmit={submit}>
          <Select label="用户" value={user || users[0] || ""} onValueChange={setUser} options={users.map(u => ({ value: u, label: u }))} />
          <Textarea label="公钥" value={key} onChange={e => setKey(e.target.value)} rows={4} required placeholder="ssh-ed25519 AAAA… user@host" />
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
            <Button type="submit" loading={busy} disabled={!key.trim() || users.length === 0}>添加</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
