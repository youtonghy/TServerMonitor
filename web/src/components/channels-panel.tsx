import { useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { Switch } from "@/components/arc/switch/switch";
import { api } from "@/api/client";
import type { ChannelEvent, ChannelInput, ChannelKind, EmailConfig, NotifyChannel, Severity, TelegramConfig, WebhookChannelConfig } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { Section, errorMessage } from "@/components/panel";
import { severityLabel } from "@/lib/labels";
import styles from "@/pages/pages.module.css";
import local from "@/pages/settings.module.css";

const toError = (e: unknown) => errorMessage(e instanceof Error ? e : new Error(String(e)));

const KINDS: { value: ChannelKind; label: string }[] = [
  { value: "email", label: "邮件（SMTP）" },
  { value: "telegram", label: "Telegram 机器人" },
  { value: "webhook", label: "Webhook" },
];
const KIND_LABEL: Record<ChannelKind, string> = { email: "邮件", telegram: "Telegram", webhook: "Webhook" };
const SEVERITIES = [
  { value: "critical", label: "仅严重" },
  { value: "warning", label: "警告及以上" },
  { value: "info", label: "全部" },
];
const EVENT_LABEL: Record<ChannelEvent, string> = { alert: "告警", report: "日报与严重事件报告", digest: "每小时警告摘要" };

/** Notification channels: config-file ones are read-only, dashboard ones editable with a test send. */
export function ChannelsPanel() {
  const channels = useQuery(() => api.channels(), []);
  const [editing, setEditing] = useState<NotifyChannel | ChannelKind | null>(null);
  const [notice, setNotice] = useState<{ tone: "success" | "danger"; text: string } | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  const test = async (c: NotifyChannel) => {
    setTesting(c.id);
    try {
      await api.testChannel(c.id);
      setNotice({ tone: "success", text: `测试消息已发送到「${c.name}」` });
    } catch (e) {
      setNotice({ tone: "danger", text: toError(e) });
    } finally {
      setTesting(null);
    }
  };

  const remove = async (c: NotifyChannel) => {
    if (!window.confirm(`删除通知渠道「${c.name}」？`)) return;
    try {
      await api.deleteChannel(c.id);
      channels.reload();
    } catch (e) {
      setNotice({ tone: "danger", text: toError(e) });
    }
  };

  return (
    <>
      {notice && <Alert tone={notice.tone} title={notice.tone === "success" ? "完成" : "失败"} onDismiss={() => setNotice(null)}>{notice.text}</Alert>}
      <Section
        title="通知渠道"
        description="告警、日报和警告摘要通过这些渠道发送。同一告警在冷却期内不重复通知。"
        actions={<div className={local.inlineSelect}><Select label="添加渠道" options={KINDS} placeholder="添加渠道…" value="" onValueChange={v => setEditing(v as ChannelKind)} /></div>}
        query={channels}
        isEmpty={d => d.channels.length === 0}
        empty={{ title: "还没有通知渠道", description: "添加邮件、Telegram 或 Webhook，告警就会推送出去。" }}
      >
        {d => (
          <ul className={styles.list}>
            {d.channels.map(c => (
              <li key={c.id} className={local.providerRow}>
                <div className={local.providerMain}>
                  <p className={styles.itemTitle}>{c.name}</p>
                  <p className={styles.textSecondary}>{describe(c)}</p>
                  <div className={local.badges}>
                    <Badge size="sm">{KIND_LABEL[c.kind]}</Badge>
                    {c.source === "config" && <Badge size="sm" tone="info">配置文件（只读）</Badge>}
                    <Badge size="sm" tone={c.enabled ? "success" : "neutral"} dot>{c.enabled ? "已启用" : "已停用"}</Badge>
                    {c.kind !== "webhook" && <Badge size="sm" outline>{severityLabel[c.min_severity]}及以上</Badge>}
                    {c.events.map(e => <Badge key={e} size="sm" outline>{EVENT_LABEL[e]}</Badge>)}
                    {c.kind === "telegram" && (c.config as TelegramConfig).bot_enabled && <Badge size="sm" tone="info">机器人指令</Badge>}
                  </div>
                </div>
                <div className={local.rowActions}>
                  <Button size="sm" variant="secondary" onClick={() => test(c)} loading={testing === c.id}>发送测试</Button>
                  {c.source === "db" && <Button size="sm" variant="ghost" onClick={() => setEditing(c)}>编辑</Button>}
                  {c.source === "db" && <Button size="sm" variant="ghost" onClick={() => remove(c)}>删除</Button>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>
      {editing !== null && (
        <ChannelDialog
          key={typeof editing === "string" ? editing : editing.id}
          channel={typeof editing === "string" ? null : editing}
          kind={typeof editing === "string" ? editing : editing.kind}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); channels.reload(); setNotice({ tone: "success", text: "通知渠道已保存，可以点“发送测试”确认能收到" }); }}
        />
      )}
    </>
  );
}

function describe(c: NotifyChannel): string {
  if (c.kind === "email") {
    const e = c.config as EmailConfig;
    return `${e.host}:${e.port} → ${e.to.join(", ")}`;
  }
  if (c.kind === "telegram") return `chat_id ${(c.config as TelegramConfig).chat_id}`;
  return (c.config as WebhookChannelConfig).url;
}

interface Draft {
  name: string; enabled: boolean; min_severity: Severity; events: ChannelEvent[]; secret: string;
  // email
  host: string; port: string; security: EmailConfig["security"]; username: string; from: string; to: string;
  // telegram
  chat_id: string; api_base: string; bot_enabled: boolean; allowed: string;
  // webhook
  url: string;
}

function draftOf(c: NotifyChannel | null, kind: ChannelKind): Draft {
  const d: Draft = {
    name: c?.name ?? KIND_LABEL[kind], enabled: c?.enabled ?? true, min_severity: c?.min_severity ?? "critical",
    events: c?.events ?? (kind === "webhook" ? ["alert", "report"] : ["alert", "digest"]), secret: "",
    host: "", port: "587", security: "starttls", username: "", from: "", to: "",
    chat_id: "", api_base: "https://api.telegram.org", bot_enabled: false, allowed: "",
    url: "",
  };
  if (c?.kind === "email") {
    const e = c.config as EmailConfig;
    Object.assign(d, { host: e.host, port: String(e.port), security: e.security, username: e.username, from: e.from, to: e.to.join(", ") });
  }
  if (c?.kind === "telegram") {
    const t = c.config as TelegramConfig;
    Object.assign(d, { chat_id: t.chat_id, api_base: t.api_base, bot_enabled: t.bot_enabled, allowed: t.allowed_user_ids.join(", ") });
  }
  if (c?.kind === "webhook") d.url = (c.config as WebhookChannelConfig).url;
  return d;
}

function configOf(kind: ChannelKind, d: Draft): ChannelInput["config"] {
  if (kind === "email") {
    return { host: d.host.trim(), port: Number(d.port), security: d.security, username: d.username.trim(), from: d.from.trim(), to: d.to.split(/[,，\s]+/).filter(Boolean) };
  }
  if (kind === "telegram") {
    return { chat_id: d.chat_id.trim(), api_base: d.api_base.trim(), bot_enabled: d.bot_enabled, allowed_user_ids: d.allowed.split(/[,，\s]+/).filter(Boolean).map(Number).filter(Number.isFinite) };
  }
  return { url: d.url.trim() };
}

const SECRET_LABEL: Record<ChannelKind, string> = { email: "SMTP 密码", telegram: "机器人令牌（Bot Token）", webhook: "签名密钥（可选）" };

function ChannelDialog({ channel, kind, onClose, onSaved }: { channel: NotifyChannel | null; kind: ChannelKind; onClose: () => void; onSaved: () => void }) {
  const [d, setD] = useState<Draft>(() => draftOf(channel, kind));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD(x => ({ ...x, [k]: v }));
  const toggleEvent = (e: ChannelEvent, on: boolean) => set("events", on ? [...new Set([...d.events, e])] : d.events.filter(x => x !== e));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    const input: ChannelInput = { kind, name: d.name.trim(), enabled: d.enabled, min_severity: d.min_severity, events: d.events, config: configOf(kind, d) };
    if (d.secret.trim()) input.secret = d.secret.trim();
    try {
      if (channel) await api.updateChannel(channel.id, input);
      else await api.createChannel(input);
      onSaved();
    } catch (e) {
      setError(toError(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={open => { if (!open) onClose(); }}>
      <DialogContent title={channel ? `编辑 ${channel.name}` : `添加${KIND_LABEL[kind]}渠道`} description="密钥加密保存在本机，只写不读；修改目标地址时需要重新填写。">
        <form className={local.form} onSubmit={submit}>
          <Input label="名称" value={d.name} onChange={e => set("name", e.target.value)} required maxLength={64} />
          {kind === "email" && (
            <>
              <div className={local.modelRow}>
                <Input label="SMTP 服务器" value={d.host} onChange={e => set("host", e.target.value)} required placeholder="smtp.example.com" />
                <Input label="端口" type="number" value={d.port} onChange={e => set("port", e.target.value)} required />
              </div>
              <Select label="加密方式" options={[{ value: "starttls", label: "STARTTLS（通常 587）" }, { value: "tls", label: "SSL/TLS（通常 465）" }, { value: "none", label: "不加密（仅内网中继）" }]} value={d.security} onValueChange={v => set("security", v as EmailConfig["security"])} />
              <Input label="用户名" value={d.username} onChange={e => set("username", e.target.value)} autoComplete="off" description="不需要登录的中继可留空" />
              <Input label="发件人" value={d.from} onChange={e => set("from", e.target.value)} required placeholder="TServerMonitor <monitor@example.com>" />
              <Input label="收件人" value={d.to} onChange={e => set("to", e.target.value)} required description="多个地址用逗号分隔" />
            </>
          )}
          {kind === "telegram" && (
            <>
              <Input label="chat_id" value={d.chat_id} onChange={e => set("chat_id", e.target.value)} required description="私聊为你的用户 id，群组为负数 id" />
              <Input label="API 地址" value={d.api_base} onChange={e => set("api_base", e.target.value)} />
              <Switch label="响应机器人指令（/status /alerts /report /ack）" checked={d.bot_enabled} onCheckedChange={v => set("bot_enabled", v)} />
              {d.bot_enabled && <Input label="允许发指令的用户 id" value={d.allowed} onChange={e => set("allowed", e.target.value)} description="群组中建议填写；留空表示该聊天中的任何人。同一个机器人令牌只能被一个程序轮询。" />}
            </>
          )}
          {kind === "webhook" && <Input label="URL" value={d.url} onChange={e => set("url", e.target.value)} required inputMode="url" description="POST JSON；设置签名密钥后带 X-TSM-Signature: sha256=<HMAC>" />}
          <Input
            label={SECRET_LABEL[kind]}
            type="password"
            autoComplete="off"
            value={d.secret}
            onChange={e => set("secret", e.target.value)}
            placeholder={channel?.has_secret ? "已保存，留空则不修改" : ""}
          />
          {kind !== "webhook" && <Select label="告警级别" options={SEVERITIES} value={d.min_severity} onValueChange={v => set("min_severity", v as Severity)} />}
          <fieldset className={local.fieldset}>
            <legend>发送内容</legend>
            {(Object.keys(EVENT_LABEL) as ChannelEvent[]).filter(e => kind !== "webhook" || e !== "digest").map(e => (
              <Switch key={e} label={EVENT_LABEL[e]} checked={d.events.includes(e)} onCheckedChange={v => toggleEvent(e, v)} />
            ))}
          </fieldset>
          <Switch label="启用" checked={d.enabled} onCheckedChange={v => set("enabled", v)} />
          {error && <Alert tone="danger" title="保存失败">{error}</Alert>}
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
            <Button type="submit" loading={saving}>保存</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
