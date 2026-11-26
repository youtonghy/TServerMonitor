// Settings: password, administrator accounts, signed-in sessions and API tokens.
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { CopyButton } from "@/components/arc/copy-button/copy-button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { api } from "@/api/client";
import type { ApiTokenRecord } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { formatDateTime, formatRelative } from "@/lib/format";
import { useAuth } from "./auth-context";
import { ConfirmDialog } from "./confirm-dialog";
import { Panel, Section, errorMessage, useNow } from "./panel";
import styles from "@/pages/pages.module.css";
import local from "@/pages/settings.module.css";

const toError = (e: unknown) => errorMessage(e instanceof Error ? e : new Error(String(e)));
const SCOPE_LABEL = { read: "只读", ops: "运维" } as const;

function browser(ua: string | null): string {
  if (!ua) return "未知客户端";
  const m = /(Firefox|Edg|Chrome|Safari)\/[\d.]+/.exec(ua);
  const os = /(Windows|Mac OS X|Android|iPhone|Linux)/.exec(ua);
  return [m?.[1]?.replace("Edg", "Edge"), os?.[1]?.replace("Mac OS X", "macOS")].filter(Boolean).join(" · ") || ua.slice(0, 40);
}

export function AccountPanel() {
  const now = useNow();
  const { user } = useAuth();
  const users = useQuery(() => api.users(), []);
  const sessions = useQuery(() => api.sessions(), []);
  const tokens = useQuery(() => api.tokens(), []);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [addingUser, setAddingUser] = useState(false);
  const [addingToken, setAddingToken] = useState(false);
  const [created, setCreated] = useState<{ token: string; record: ApiTokenRecord } | null>(null);
  const [confirm, setConfirm] = useState<{ title: string; description: string; run: () => Promise<unknown>; requireText?: string } | null>(null);

  const act = async (fn: () => Promise<unknown>, done: string, reload: () => void) => {
    setError(null);
    try {
      await fn();
      setNotice(done);
      reload();
    } catch (e) {
      setError(toError(e));
    }
  };

  return (
    <>
      {error && <Alert tone="danger" title="操作失败" onDismiss={() => setError(null)}>{error}</Alert>}
      {notice && <Alert tone="success" title="完成" onDismiss={() => setNotice(null)}>{notice}</Alert>}

      <PasswordPanel onDone={() => { setNotice("密码已修改，其他设备上的登录已全部退出"); sessions.reload(); }} />

      <Section
        title="管理员"
        description="每个账号都拥有完整权限；管理账号前需要确认密码"
        actions={<Button size="sm" variant="secondary" onClick={() => setAddingUser(true)}>添加管理员</Button>}
        query={users}
      >
        {d => (
          <ul className={styles.list}>
            {d.map(u => (
              <li key={u.id} className={local.providerRow}>
                <div className={local.providerMain}>
                  <span className={styles.row}><span className={styles.strong}>{u.username}</span>{u.id === user?.id && <Badge size="sm" tone="info">当前账号</Badge>}</span>
                  <span className={`${styles.small} ${styles.muted}`}>创建于 {formatDateTime(u.created_at)} · {u.last_login_at ? `最近登录 ${formatRelative(u.last_login_at, now)}` : "从未登录"}</span>
                </div>
                {u.id !== user?.id && d.length > 1 && (
                  <Button size="sm" variant="ghost" onClick={() => setConfirm({ title: `删除管理员 ${u.username}？`, description: "该账号的所有登录会立即失效。", requireText: u.username, run: () => act(() => api.deleteUser(u.id), `已删除 ${u.username}`, users.reload) })}>删除</Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="登录会话" description="当前账号在各设备上的登录；超过 12 小时未使用会自动退出" query={sessions}>
        {d => (
          <ul className={styles.list}>
            {d.map(s => (
              <li key={s.id} className={local.providerRow}>
                <div className={local.providerMain}>
                  <span className={styles.row}><span className={styles.strong}>{browser(s.user_agent)}</span>{s.current && <Badge size="sm" tone="success">此设备</Badge>}</span>
                  <span className={`${styles.small} ${styles.muted}`}>{s.remote ?? "未知地址"} · 登录于 {formatDateTime(s.created_at)} · 最近活动 {formatRelative(s.last_seen, now)}</span>
                </div>
                {!s.current && <Button size="sm" variant="ghost" onClick={() => act(() => api.revokeSession(s.id), "已让该设备退出登录", sessions.reload)}>退出</Button>}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section
        title="API 令牌"
        description="供 MCP 客户端和脚本使用（Authorization: Bearer）。只读令牌可访问 API 与 /mcp；运维令牌还可访问 /mcp/ops 并修改服务器，等同 root 权限"
        actions={<Button size="sm" variant="secondary" onClick={() => setAddingToken(true)}>创建令牌</Button>}
        query={tokens}
        isEmpty={d => d.length === 0}
        empty={{ title: "还没有 API 令牌", description: "接入 MCP 客户端前先创建一个只读令牌。" }}
      >
        {d => (
          <ul className={styles.list}>
            {d.map(t => {
              const expired = t.expires_at !== null && t.expires_at < now;
              const inactive = t.revoked_at !== null || expired;
              return (
                <li key={t.id} className={local.providerRow}>
                  <div className={local.providerMain}>
                    <span className={styles.row}>
                      <span className={styles.strong}>{t.name}</span>
                      <Badge size="sm" tone={t.scope === "ops" ? "warning" : "neutral"}>{SCOPE_LABEL[t.scope]}</Badge>
                      {t.revoked_at !== null && <Badge size="sm" tone="danger">已吊销</Badge>}
                      {expired && t.revoked_at === null && <Badge size="sm" tone="neutral">已过期</Badge>}
                    </span>
                    <span className={`${styles.small} ${styles.muted}`}>
                      <code className={styles.code}>{t.prefix}…</code> · 创建于 {formatDateTime(t.created_at)} · {t.expires_at ? `到期 ${formatDateTime(t.expires_at)}` : "永不过期"} · {t.last_used_at ? `最近使用 ${formatRelative(t.last_used_at, now)}` : "从未使用"}
                    </span>
                  </div>
                  {!inactive && <Button size="sm" variant="ghost" onClick={() => setConfirm({ title: `吊销令牌 ${t.name}？`, description: "使用它的客户端会立即失去访问权限。", run: () => act(() => api.revokeToken(t.id), `已吊销 ${t.name}`, tokens.reload) })}>吊销</Button>}
                </li>
              );
            })}
          </ul>
        )}
      </Section>

      <UserDialog open={addingUser} onOpenChange={setAddingUser} onCreate={async (n, p) => { await api.createUser(n, p); setNotice(`已添加管理员 ${n}`); users.reload(); }} />
      <TokenDialog open={addingToken} onOpenChange={setAddingToken} onCreate={async (n, s, d) => { const r = await api.createToken(n, s, d); setCreated(r); tokens.reload(); }} />
      <Dialog open={created !== null} onOpenChange={o => { if (!o) setCreated(null); }}>
        <DialogContent title={`令牌 ${created?.record.name ?? ""} 已创建`} description="请立即复制保存，关闭后无法再次查看。">
          <div className={local.form}>
            <code className={styles.code}>{created?.token}</code>
            <div className={local.actions}>
              {created && <CopyButton value={created.token} label="复制令牌" />}
              <Button onClick={() => setCreated(null)}>我已保存</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={o => { if (!o) setConfirm(null); }}
        title={confirm?.title ?? ""}
        description={confirm?.description}
        danger
        requireText={confirm?.requireText}
        onConfirm={async () => { await confirm?.run(); }}
      />
    </>
  );
}

function PasswordPanel({ onDone }: { onDone: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = repeat.length > 0 && repeat !== next;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (mismatch || next.length < 10) return;
    setBusy(true);
    setError(null);
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setRepeat("");
      onDone();
    } catch (err) {
      setError(toError(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Panel title="修改密码" description="修改后，除当前设备外的所有登录都会退出">
      <form className={local.form} onSubmit={submit}>
        {error && <Alert tone="danger" title="修改失败">{error}</Alert>}
        <Input label="当前密码" type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} required />
        <Input label="新密码" type="password" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} required error={next.length > 0 && next.length < 10 ? "至少 10 位" : undefined} />
        <Input label="再次输入新密码" type="password" autoComplete="new-password" value={repeat} onChange={e => setRepeat(e.target.value)} required error={mismatch ? "两次输入不一致" : undefined} />
        <div className={local.actions}>
          <Button type="submit" loading={busy} disabled={!current || next.length < 10 || mismatch}>修改密码</Button>
        </div>
      </form>
    </Panel>
  );
}

function UserDialog({ open, onOpenChange, onCreate }: { open: boolean; onOpenChange: (o: boolean) => void; onCreate: (name: string, password: string) => Promise<void> }) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onCreate(name, password);
      setName("");
      setPassword("");
      onOpenChange(false);
    } catch (err) {
      setError(toError(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="添加管理员" description="新账号拥有完整权限。">
        <form className={local.form} onSubmit={submit}>
          {error && <Alert tone="danger" title="添加失败">{error}</Alert>}
          <Input label="用户名" value={name} onChange={e => setName(e.target.value)} autoComplete="off" required minLength={3} maxLength={32} />
          <Input label="初始密码" type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" required minLength={10} description="至少 10 位，请通过安全渠道告知对方" />
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
            <Button type="submit" loading={busy}>添加</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function TokenDialog({ open, onOpenChange, onCreate }: { open: boolean; onOpenChange: (o: boolean) => void; onCreate: (name: string, scope: "read" | "ops", days: number | null) => Promise<void> }) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState<"read" | "ops">("read");
  const [days, setDays] = useState("90");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onCreate(name, scope, days === "never" ? null : Number(days));
      setName("");
      onOpenChange(false);
    } catch (err) {
      setError(toError(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="创建 API 令牌" description="令牌只在创建后显示一次。">
        <form className={local.form} onSubmit={submit}>
          {error && <Alert tone="danger" title="创建失败">{error}</Alert>}
          <Input label="名称" value={name} onChange={e => setName(e.target.value)} required maxLength={64} description="例如 claude-code 或 grafana" autoComplete="off" />
          <Select label="范围" value={scope} onValueChange={v => setScope(v as "read" | "ops")} options={[
            { value: "read", label: "只读：REST 读接口与 /mcp" },
            { value: "ops", label: "运维：另可通过 /mcp/ops 修改服务器" },
          ]} />
          <Select label="有效期" value={days} onValueChange={setDays} options={[
            { value: "30", label: "30 天" }, { value: "90", label: "90 天" }, { value: "365", label: "1 年" }, { value: "never", label: "永不过期" },
          ]} />
          {scope === "ops" && <Alert tone="warning" title="运维令牌等同 root">持有者可以在运维助手允许的范围内修改 nginx、防火墙、SSH 和 Docker。</Alert>}
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
            <Button type="submit" loading={busy} disabled={!name.trim()}>创建</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
