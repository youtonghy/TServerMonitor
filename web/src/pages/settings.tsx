import { useEffect, useRef, useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { ApiFormat, AuthStyle, Effort, Provider, ProviderInput, Route, RoutingResponse } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { AccountPanel } from "@/components/account-panel";
import { ChannelsPanel } from "@/components/channels-panel";
import { PageHeader, Panel, Section, errorMessage } from "@/components/panel";
import styles from "./pages.module.css";
import local from "./settings.module.css";

const FORMATS = [
  { value: "responses", label: "Responses（OpenAI 兼容）" },
  { value: "messages", label: "Messages（Anthropic 兼容）" },
];
const AUTHS = [
  { value: "api_key", label: "x-api-key 请求头" },
  { value: "bearer", label: "Authorization: Bearer" },
];
const EFFORT_LABEL: Record<Effort, string> = {
  "": "模型默认", none: "关闭", minimal: "最低", low: "低", medium: "中", high: "高", xhigh: "超高", max: "最大",
};
// Radix Select items cannot use an empty string as value.
const DEFAULT = "__default";
const INHERIT = "__inherit";

const toError = (e: unknown) => errorMessage(e instanceof Error ? e : new Error(String(e)));

export default function SettingsPage() {
  const providers = useQuery(() => api.providers(), []);
  const routing = useQuery(() => api.routing(), []);
  const [editing, setEditing] = useState<Provider | "new" | null>(null);
  const [notice, setNotice] = useState<{ tone: "success" | "danger"; text: string } | null>(null);

  useStreamEvent("settings", () => {
    providers.reload();
    routing.reload();
  });

  const remove = async (p: Provider) => {
    if (!window.confirm(`删除 Provider「${p.name}」？引用它的任务路由也会一并删除。`)) return;
    try {
      await api.deleteProvider(p.id);
      setNotice({ tone: "success", text: `已删除 ${p.name}` });
      providers.reload();
      routing.reload();
    } catch (e) {
      setNotice({ tone: "danger", text: toError(e) });
    }
  };

  const keyStorage = providers.data?.key_storage;

  return (
    <>
      <PageHeader title="设置" description="模型 Provider、每类任务使用的模型与思考强度，以及告警通知渠道">
        <Button onClick={() => setEditing("new")}>添加 Provider</Button>
      </PageHeader>

      {notice && (
        <Alert tone={notice.tone} title={notice.tone === "success" ? "已保存" : "操作失败"} onDismiss={() => setNotice(null)}>
          {notice.text}
        </Alert>
      )}
      {keyStorage === "unavailable" && (
        <Alert tone="warning" title="无法在界面保存密钥">
          本机的脚本沙箱无法隔离数据目录，密钥文件不安全。请为守护进程设置环境变量 TSM_SECRET_KEY 后重启，或在 config.toml 中用环境变量配置 Provider。
        </Alert>
      )}

      <Section
        title="模型 Provider"
        description="支持 OpenAI Responses 与 Anthropic Messages 两种协议。密钥加密保存，只写不读。"
        query={providers}
        isEmpty={d => d.providers.length === 0}
        empty={{ title: "还没有 Provider", description: "添加一个 Provider 后，即可为各类任务选择模型。" }}
      >
        {d => (
          <ul className={styles.list}>
            {d.providers.map(p => (
              <li key={`${p.source}:${p.id}`} className={local.providerRow}>
                <div className={local.providerMain}>
                  <p className={styles.itemTitle}>{p.name}</p>
                  <p className={styles.textSecondary}>{p.base_url}</p>
                  <div className={local.badges}>
                    <Badge size="sm">{p.api_format === "responses" ? "Responses" : "Messages"}</Badge>
                    {p.source === "config" ? <Badge size="sm" tone="info">配置文件（只读）</Badge> : null}
                    {p.has_key
                      ? <Badge size="sm" tone="success" dot>密钥已设置</Badge>
                      : <Badge size="sm" tone="warning" dot>{p.key_env ? `缺少 ${p.key_env}` : "未填写密钥"}</Badge>}
                    {p.default_model && <Badge size="sm" outline>{p.default_model}</Badge>}
                  </div>
                </div>
                {p.source === "db" && (
                  <div className={local.rowActions}>
                    <Button size="sm" variant="secondary" onClick={() => setEditing(p)}>编辑</Button>
                    <Button size="sm" variant="ghost" onClick={() => remove(p)}>删除</Button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      {routing.status === "ready" && providers.status === "ready" ? (
        <RoutingPanel key={JSON.stringify(routing.data.routes)} routing={routing.data} providers={providers.data.providers} onSaved={next => { routing.setData(() => next); setNotice({ tone: "success", text: "任务路由已更新，下一次运行生效" }); }} />
      ) : (
        <Section title="任务路由" query={routing}>{() => null}</Section>
      )}

      <ChannelsPanel />

      <AccountPanel />

      <ProviderDialog
        key={editing === null ? "closed" : editing === "new" ? "new" : editing.id}
        target={editing}
        onClose={() => setEditing(null)}
        onSaved={name => {
          setEditing(null);
          setNotice({ tone: "success", text: `Provider ${name} 已保存` });
          providers.reload();
          routing.reload();
        }}
      />
    </>
  );
}

// ---------------------------------------------------------------- provider form

interface Draft { name: string; api_format: ApiFormat; base_url: string; auth: AuthStyle; default_model: string; api_key: string }

function ProviderDialog({ target, onClose, onSaved }: { target: Provider | "new" | null; onClose: () => void; onSaved: (name: string) => void }) {
  const existing = target && target !== "new" ? target : null;
  const [draft, setDraft] = useState<Draft>(() => existing
    ? { name: existing.name, api_format: existing.api_format, base_url: existing.base_url, auth: existing.auth, default_model: existing.default_model, api_key: "" }
    : empty());
  const [models, setModels] = useState<string[] | null>(null);
  const [fetching, setFetching] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft(d => ({ ...d, [key]: value }));
  const urlChanged = existing ? existing.base_url !== draft.base_url.trim().replace(/\/+$/, "") : false;

  const fetchModels = async () => {
    setFetching(true);
    setError(null);
    try {
      const { models: list } = await api.listModels({
        provider_id: existing?.id,
        api_format: draft.api_format,
        base_url: draft.base_url.trim(),
        auth: draft.auth,
        api_key: draft.api_key.trim() || undefined,
      });
      setModels(list);
      if (list.length === 0) setError("接口没有返回任何模型，请手动填写模型名");
    } catch (e) {
      setModels(null);
      setError(`${toError(e)}。可以直接手动填写模型名。`);
    } finally {
      setFetching(false);
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    const input: ProviderInput = {
      name: draft.name.trim(),
      api_format: draft.api_format,
      base_url: draft.base_url.trim(),
      auth: draft.auth,
      default_model: draft.default_model.trim(),
    };
    if (draft.api_key.trim()) input.api_key = draft.api_key.trim();
    try {
      if (existing) await api.updateProvider(existing.id, input);
      else await api.createProvider(input);
      onSaved(input.name ?? "");
    } catch (e) {
      setError(toError(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={target !== null} onOpenChange={open => { if (!open) onClose(); }}>
      <DialogContent title={existing ? `编辑 ${existing.name}` : "添加 Provider"} description="填写接口地址后可以拉取模型列表；拉取失败时可直接手动填写模型名。">
        <form className={local.form} onSubmit={submit}>
          <Input label="名称" value={draft.name} onChange={e => set("name", e.target.value)} required maxLength={64} />
          <Select label="协议" options={FORMATS} value={draft.api_format} onValueChange={v => set("api_format", v as ApiFormat)} />
          <Input
            label="接口地址（base_url）"
            description={draft.api_format === "responses" ? "例如 https://api.openai.com/v1，请求会发到 {base_url}/responses" : "例如 https://api.anthropic.com/v1，请求会发到 {base_url}/messages"}
            value={draft.base_url}
            onChange={e => set("base_url", e.target.value)}
            required
            inputMode="url"
          />
          {draft.api_format === "messages" && (
            <Select label="密钥发送方式" options={AUTHS} value={draft.auth} onValueChange={v => set("auth", v as AuthStyle)} />
          )}
          <Input
            label="API 密钥"
            type="password"
            autoComplete="off"
            value={draft.api_key}
            onChange={e => set("api_key", e.target.value)}
            placeholder={existing?.has_key ? "已保存，留空则不修改" : ""}
            description={urlChanged && existing?.has_key ? "修改了接口地址，必须重新填写密钥" : "只写不读，加密保存在本机"}
          />
          <div className={local.modelRow}>
            <Input
              label="默认模型"
              value={draft.default_model}
              onChange={e => set("default_model", e.target.value)}
              list="provider-models"
              placeholder="拉取列表后选择，或手动填写"
            />
            <Button type="button" variant="secondary" onClick={fetchModels} loading={fetching} disabled={!draft.base_url.trim()}>
              拉取模型列表
            </Button>
          </div>
          <datalist id="provider-models">{models?.map(m => <option key={m} value={m} />)}</datalist>
          {models && models.length > 0 && (
            <Select label={`可用模型（${models.length}）`} options={models.map(m => ({ value: m, label: m }))} value={models.includes(draft.default_model) ? draft.default_model : undefined} placeholder="选择一个模型" onValueChange={v => set("default_model", v)} />
          )}
          {error && <Alert tone="warning" title="提示">{error}</Alert>}
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={onClose}>取消</Button>
            <Button type="submit" loading={saving}>保存</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function empty(): Draft {
  return { name: "", api_format: "responses", base_url: "", auth: "api_key", default_model: "", api_key: "" };
}

// ---------------------------------------------------------------- routing

function RoutingPanel({ routing, providers, onSaved }: { routing: RoutingResponse; providers: Provider[]; onSaved: (next: RoutingResponse) => void }) {
  const [rows, setRows] = useState<Record<string, Route>>(() => index(routing.routes));
  const [models, setModels] = useState<Record<string, string[]>>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // model suggestions per provider, loaded once when first needed; failures just mean no suggestions
  const requested = useRef(new Set<string>());
  const wanted = [...new Set(Object.values(rows).map(r => r.provider))].filter(Boolean).join(",");
  useEffect(() => {
    for (const id of wanted.split(",").filter(Boolean)) {
      if (requested.current.has(id)) continue;
      requested.current.add(id);
      api.listModels({ provider_id: id }).then(r => setModels(m => ({ ...m, [id]: r.models })), () => undefined);
    }
  }, [wanted]);

  const providerOptions = providers.map(p => ({ value: p.id, label: p.source === "config" ? `${p.name}（配置文件）` : p.name }));

  const update = (kind: string, patch: Partial<Route>) => setRows(r => {
    const base = r[kind] ?? { kind, provider: "", model: "", effort: "" as Effort };
    return { ...r, [kind]: { ...base, ...patch } };
  });
  const clear = (kind: string) => setRows(r => {
    const next = { ...r };
    delete next[kind];
    return next;
  });

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      onSaved(await api.saveRouting(Object.values(rows).filter(r => r.provider)));
    } catch (e) {
      setError(toError(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Panel
      title="任务路由"
      description="为每类任务指定 Provider、模型和思考强度。未单独设置的任务使用“默认”这一行。"
      actions={<Button onClick={save} loading={saving} disabled={providers.length === 0}>保存路由</Button>}
    >
      {error && <Alert tone="danger" title="保存失败" onDismiss={() => setError(null)}>{error}</Alert>}
      <ul className={styles.list}>
        {routing.kinds.map(({ kind, label, resolved }) => {
          const row = rows[kind];
          const isDefault = kind === "default";
          const provider = providers.find(p => p.id === row?.provider);
          return (
            <li key={kind} className={local.routeRow}>
              <div className={local.routeLabel}>
                <p className={styles.itemTitle}>{label}</p>
                <p className={styles.textSecondary}>
                  {resolved ? `当前：${resolved.model}${resolved.effort ? ` · 思考${EFFORT_LABEL[resolved.effort]}` : ""}` : "当前：未配置"}
                </p>
              </div>
              <Select
                label="Provider"
                options={[...(isDefault ? [] : [{ value: INHERIT, label: "跟随默认" }]), ...providerOptions]}
                value={row?.provider || (isDefault ? undefined : INHERIT)}
                placeholder="选择 Provider"
                onValueChange={v => (v === INHERIT ? clear(kind) : update(kind, { provider: v }))}
              />
              <Input
                label="模型"
                value={row?.model ?? ""}
                disabled={!row}
                placeholder={provider?.default_model ? `默认 ${provider.default_model}` : "填写模型名"}
                list={row ? `models-${kind}` : undefined}
                onChange={e => update(kind, { model: e.target.value })}
              />
              <datalist id={`models-${kind}`}>{(row && models[row.provider] || []).map(m => <option key={m} value={m} />)}</datalist>
              <Select
                label="思考强度"
                options={routing.efforts.map(e => ({ value: e || DEFAULT, label: EFFORT_LABEL[e] }))}
                value={row ? row.effort || DEFAULT : DEFAULT}
                disabled={!row}
                onValueChange={v => update(kind, { effort: (v === DEFAULT ? "" : v) as Effort })}
              />
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

function index(routes: Route[]): Record<string, Route> {
  return Object.fromEntries(routes.map(r => [r.kind, { ...r }]));
}
