import { useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { Select } from "@/components/arc/select/select";
import { Switch } from "@/components/arc/switch/switch";
import { Textarea } from "@/components/arc/textarea/textarea";
import { api } from "@/api/client";
import type { Prompt, Task, TaskInput, Trigger } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { PageHeader, Section, errorMessage, useNow } from "@/components/panel";
import { formatRelative } from "@/lib/format";
import { lookup, taskKindLabel } from "@/lib/labels";
import { Link } from "@/lib/router";
import styles from "./pages.module.css";
import local from "./settings.module.css";

const toError = (e: unknown) => errorMessage(e instanceof Error ? e : new Error(String(e)));

const TABS = [
  { value: "tasks", label: "自动任务" },
  { value: "prompts", label: "提示词库" },
];

const TRIGGER_TYPES = [
  { value: "daily", label: "每天定点" },
  { value: "interval", label: "固定间隔" },
  { value: "log_threshold", label: "日志数量达到阈值" },
  { value: "burst", label: "日志突增时" },
  { value: "manual", label: "仅手动运行" },
];

const ROUTE_KINDS = [
  { value: "default", label: "默认" },
  { value: "log_scan", label: "日志扫描" },
  { value: "security_check", label: "安全体检" },
  { value: "package_advice", label: "包更新建议" },
  { value: "audit", label: "深度审计" },
  { value: "daily", label: "每日运维简报" },
  { value: "hourly", label: "小时巡检" },
  { value: "incident", label: "异常事件分析" },
];

function describeTrigger(t: Trigger): string {
  switch (t.type) {
    case "interval": return t.every_mins % 60 === 0 ? `每 ${t.every_mins / 60} 小时` : `每 ${t.every_mins} 分钟`;
    case "daily": return `每天 ${t.at}`;
    case "log_threshold": return `${t.source ?? "全部日志"}${t.metric === "errors" ? "错误数" : "日志行数"}累计达到 ${t.count}（间隔至少 ${t.min_interval_mins} 分钟）`;
    case "burst": return "日志错误突增时";
    case "manual": return "仅手动运行";
  }
}

export default function TasksPage() {
  const [tab, setTab] = useState("tasks");
  return (
    <>
      <PageHeader title="自动任务" description="让 Agent 定期巡检、按日志量或突增自动扫日志、每天做安全体检；任务内容来自提示词库">
        <SegmentedControl label="视图" options={TABS} value={tab} onValueChange={setTab} />
      </PageHeader>
      {tab === "tasks" ? <TasksView /> : <PromptsView />}
    </>
  );
}

// ---------------------------------------------------------------- tasks

function TasksView() {
  const now = useNow();
  const tasks = useQuery(() => api.tasks(), []);
  const prompts = useQuery(() => api.prompts(), []);
  const [editing, setEditing] = useState<Task | "new" | null>(null);
  const [notice, setNotice] = useState<{ tone: "success" | "danger" | "info"; text: string; runId?: string | null } | null>(null);

  const promptName = (id: string) => prompts.data?.find(p => p.id === id)?.name ?? id;

  const toggle = async (t: Task, enabled: boolean) => {
    tasks.setData(prev => prev && { ...prev, tasks: prev.tasks.map(x => x.id === t.id ? { ...x, enabled } : x) });
    try {
      await api.updateTask(t.id, { enabled });
    } catch (e) {
      setNotice({ tone: "danger", text: toError(e) });
      tasks.reload();
    }
  };

  const run = async (t: Task) => {
    try {
      const r = await api.runTask(t.id);
      setNotice(r.run_id
        ? { tone: "success", text: `已开始运行「${t.name}」`, runId: r.run_id }
        : { tone: "info", text: `「${t.name}」已排队：当前有其他分析在运行或主机繁忙，稍后会自动执行` });
      tasks.reload();
    } catch (e) {
      setNotice({ tone: "danger", text: toError(e) });
    }
  };

  const remove = async (t: Task) => {
    if (!window.confirm(`删除任务「${t.name}」？`)) return;
    try {
      await api.deleteTask(t.id);
      tasks.reload();
    } catch (e) {
      setNotice({ tone: "danger", text: toError(e) });
    }
  };

  return (
    <>
      {notice && (
        <Alert tone={notice.tone} title={notice.tone === "danger" ? "操作失败" : "提示"} onDismiss={() => setNotice(null)}>
          {notice.text}{notice.runId && <> · <Link to={`/agent/c_${notice.runId}`}>在控制台查看</Link></>}
        </Alert>
      )}
      <Section
        title="任务"
        description="每个任务运行一次 Agent 分析并生成报告，过程可在 Agent 控制台查看。"
        actions={<Button size="sm" onClick={() => setEditing("new")}>新建任务</Button>}
        query={tasks}
        isEmpty={d => d.tasks.length === 0}
        empty={{ title: "还没有任务", description: "新建一个任务，例如每 6 小时扫描一次日志。" }}
      >
        {d => (
          <ul className={styles.list}>
            {d.tasks.map(t => (
              <li key={t.id} className={local.providerRow}>
                <div className={local.providerMain}>
                  <p className={styles.itemTitle}>{t.name}</p>
                  <p className={styles.textSecondary}>{describeTrigger(t.trigger)} · 提示词：{promptName(t.prompt_id)} · 模型路由：{lookup(taskKindLabel, t.route_kind)}</p>
                  <div className={local.badges}>
                    {t.builtin && <Badge size="sm" tone="info">内置</Badge>}
                    <Badge size="sm" tone={t.enabled ? "success" : "neutral"} dot>{t.enabled ? "已启用" : "已停用"}</Badge>
                    <span className={`${styles.muted} ${styles.small}`}>
                      {t.last_fired_at ? `上次运行 ${formatRelative(t.last_fired_at, now)}` : "尚未运行"}
                      {t.last_run_id && <> · <Link to={`/agent/c_${t.last_run_id}`}>查看过程</Link></>}
                    </span>
                  </div>
                </div>
                <div className={local.rowActions}>
                  <Switch label="启用" checked={t.enabled} onCheckedChange={v => toggle(t, v)} />
                  <Button size="sm" variant="secondary" onClick={() => run(t)}>立即运行</Button>
                  <Button size="sm" variant="ghost" onClick={() => setEditing(t)}>编辑</Button>
                  {!t.builtin && <Button size="sm" variant="ghost" onClick={() => remove(t)}>删除</Button>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="系统内置调度" description="来自 config.toml 的 [schedule]，在配置文件中修改；使用的提示词可在提示词库查看。" query={tasks}>
        {d => (
          <ul className={styles.list}>
            {d.system.map(j => (
              <li key={j.id}>
                <p className={styles.itemTitle}>{j.name}</p>
                <p className={styles.textSecondary}>{j.trigger} · 提示词：{promptName(j.prompt_id)}</p>
                <div className={local.badges}><Badge size="sm" tone={j.enabled ? "success" : "neutral"} dot>{j.enabled ? "已启用" : "已停用"}</Badge></div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      {editing !== null && prompts.status === "ready" && (
        <TaskDialog
          key={editing === "new" ? "new" : editing.id}
          task={editing === "new" ? null : editing}
          prompts={prompts.data}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); tasks.reload(); setNotice({ tone: "success", text: "任务已保存" }); }}
        />
      )}
    </>
  );
}

interface TaskDraft {
  name: string; enabled: boolean; type: Trigger["type"];
  every_mins: string; at: string;
  source: string; metric: "lines" | "errors"; count: string; min_interval_mins: string;
  prompt_id: string; route_kind: string;
}

function draftOf(t: Task | null): TaskDraft {
  const d: TaskDraft = {
    name: t?.name ?? "", enabled: t?.enabled ?? true, type: t?.trigger.type ?? "daily",
    every_mins: "360", at: "03:00", source: "", metric: "errors", count: "100", min_interval_mins: "60",
    prompt_id: t?.prompt_id ?? "builtin:log_scan", route_kind: t?.route_kind ?? "log_scan",
  };
  const tr = t?.trigger;
  if (tr?.type === "interval") d.every_mins = String(tr.every_mins);
  if (tr?.type === "daily") d.at = tr.at;
  if (tr?.type === "log_threshold") Object.assign(d, { source: tr.source ?? "", metric: tr.metric, count: String(tr.count), min_interval_mins: String(tr.min_interval_mins) });
  return d;
}

function triggerOf(d: TaskDraft): Trigger {
  switch (d.type) {
    case "interval": return { type: "interval", every_mins: Number(d.every_mins) };
    case "daily": return { type: "daily", at: d.at };
    case "log_threshold": return { type: "log_threshold", source: d.source || null, metric: d.metric, count: Number(d.count), min_interval_mins: Number(d.min_interval_mins) };
    case "burst": return { type: "burst" };
    case "manual": return { type: "manual" };
  }
}

const ALL_SOURCES = "__all";

function TaskDialog({ task, prompts, onClose, onSaved }: { task: Task | null; prompts: Prompt[]; onClose: () => void; onSaved: () => void }) {
  const [d, setD] = useState<TaskDraft>(() => draftOf(task));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sources = useQuery(() => api.logSources(), []);
  const set = <K extends keyof TaskDraft>(k: K, v: TaskDraft[K]) => setD(x => ({ ...x, [k]: v }));

  const choosePrompt = (id: string) => {
    const p = prompts.find(x => x.id === id);
    setD(x => ({ ...x, prompt_id: id, route_kind: p && p.route_kind !== "default" ? p.route_kind : x.route_kind }));
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    const input: TaskInput = { name: d.name.trim(), enabled: d.enabled, trigger: triggerOf(d), prompt_id: d.prompt_id, route_kind: d.route_kind };
    try {
      if (task) await api.updateTask(task.id, input);
      else await api.createTask(input);
      onSaved();
    } catch (err) {
      setError(toError(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={open => { if (!open) onClose(); }}>
      <DialogContent title={task ? `编辑 ${task.name}` : "新建任务"} description="触发时运行一次 Agent 分析，使用所选提示词作为任务说明。">
        <form className={local.form} onSubmit={submit}>
          <Input label="名称" value={d.name} onChange={e => set("name", e.target.value)} required maxLength={64} />
          <Select label="触发方式" options={TRIGGER_TYPES} value={d.type} onValueChange={v => set("type", v as Trigger["type"])} />
          {d.type === "interval" && (
            <Input label="间隔（分钟）" type="number" min={5} max={10080} value={d.every_mins} onChange={e => set("every_mins", e.target.value)} description="5 分钟到 7 天；首次运行在创建一个间隔之后" />
          )}
          {d.type === "daily" && <Input label="每天运行时间" type="time" value={d.at} onChange={e => set("at", e.target.value)} />}
          {d.type === "log_threshold" && (
            <>
              <Select
                label="日志源"
                options={[{ value: ALL_SOURCES, label: "全部日志源" }, ...(sources.data ?? []).map(s => ({ value: s.name, label: s.name }))]}
                value={d.source || ALL_SOURCES}
                onValueChange={v => set("source", v === ALL_SOURCES ? "" : v)}
              />
              <Select label="统计" options={[{ value: "errors", label: "错误数" }, { value: "lines", label: "日志行数" }]} value={d.metric} onValueChange={v => set("metric", v as "lines" | "errors")} />
              <Input label="阈值" type="number" min={1} value={d.count} onChange={e => set("count", e.target.value)} description="自上次运行以来累计达到这个数量就触发" />
              <Input label="最小间隔（分钟）" type="number" min={5} value={d.min_interval_mins} onChange={e => set("min_interval_mins", e.target.value)} />
            </>
          )}
          <Select label="提示词" options={prompts.map(p => ({ value: p.id, label: p.builtin ? `${p.name}（内置）` : p.name }))} value={d.prompt_id} onValueChange={choosePrompt} />
          <Select label="模型路由" description="决定使用哪个模型，在设置页的任务路由中配置" options={ROUTE_KINDS} value={d.route_kind} onValueChange={v => set("route_kind", v)} />
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

// ---------------------------------------------------------------- prompts

function PromptsView() {
  const prompts = useQuery(() => api.prompts(), []);
  const [editing, setEditing] = useState<{ prompt: Prompt | null; copy?: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const remove = async (p: Prompt) => {
    if (!window.confirm(`删除提示词「${p.name}」？`)) return;
    try {
      await api.deletePrompt(p.id);
      prompts.reload();
    } catch (e) {
      setError(toError(e));
    }
  };

  return (
    <>
      {error && <Alert tone="danger" title="操作失败" onDismiss={() => setError(null)}>{error}</Alert>}
      <Section
        title="提示词库"
        description="提示词是任务说明。系统提示词（只读、不信任日志中的指令等安全规则）始终会附加在前面，不能被替换。"
        actions={<Button size="sm" onClick={() => setEditing({ prompt: null })}>新建提示词</Button>}
        query={prompts}
      >
        {data => (
          <ul className={styles.list}>
            {data.map(p => (
              <li key={p.id} className={local.providerRow}>
                <div className={local.providerMain}>
                  <p className={styles.itemTitle}>{p.name}</p>
                  {p.description && <p className={styles.textSecondary}>{p.description}</p>}
                  <div className={local.badges}>{p.builtin ? <Badge size="sm" tone="info">内置</Badge> : <Badge size="sm">自定义</Badge>}</div>
                </div>
                <div className={local.rowActions}>
                  {p.builtin
                    ? <>
                        <Button size="sm" variant="ghost" onClick={() => setEditing({ prompt: p })}>查看</Button>
                        <Button size="sm" variant="secondary" onClick={() => setEditing({ prompt: p, copy: true })}>复制</Button>
                      </>
                    : <>
                        <Button size="sm" variant="secondary" onClick={() => setEditing({ prompt: p })}>编辑</Button>
                        <Button size="sm" variant="ghost" onClick={() => remove(p)}>删除</Button>
                      </>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>
      {editing && (
        <PromptDialog
          key={`${editing.prompt?.id ?? "new"}-${editing.copy ? "copy" : ""}`}
          prompt={editing.prompt}
          copy={editing.copy ?? false}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); prompts.reload(); }}
        />
      )}
    </>
  );
}

function PromptDialog({ prompt, copy, onClose, onSaved }: { prompt: Prompt | null; copy: boolean; onClose: () => void; onSaved: () => void }) {
  const readOnly = Boolean(prompt?.builtin && !copy);
  const editingExisting = Boolean(prompt && !prompt.builtin && !copy);
  const [name, setName] = useState(prompt ? (copy ? `${prompt.name.replace(/（系统内置）$/, "")}（副本）` : prompt.name) : "");
  const [description, setDescription] = useState(prompt?.description ?? "");
  const [body, setBody] = useState(prompt?.body ?? "");
  const [idea, setIdea] = useState("");
  const [generating, setGenerating] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = async () => {
    setGenerating(true);
    setError(null);
    try {
      const r = await api.generatePrompt(idea.trim());
      setBody(r.body);
      if (!name.trim()) setName(idea.trim().slice(0, 30));
    } catch (e) {
      setError(toError(e));
    } finally {
      setGenerating(false);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (readOnly) return onClose();
    setSaving(true);
    setError(null);
    try {
      const input = { name: name.trim(), description: description.trim(), body: body.trim() };
      if (editingExisting && prompt) await api.updatePrompt(prompt.id, input);
      else await api.createPrompt(input);
      onSaved();
    } catch (err) {
      setError(toError(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open onOpenChange={open => { if (!open) onClose(); }}>
      <DialogContent title={readOnly ? prompt!.name : editingExisting ? "编辑提示词" : "新建提示词"} description={readOnly ? "内置提示词只读，可以复制后修改。{trigger} 会被替换为触发原因。" : "写清楚要检查什么、判断标准是什么、希望输出什么建议。{trigger} 会被替换为触发原因。"}>
        <form className={local.form} onSubmit={submit}>
          {!readOnly && (
            <div className={local.form}>
              <Textarea label="用一句话描述，让 Agent 生成草稿" value={idea} onChange={e => setIdea(e.target.value)} rows={2} placeholder="例如：每天检查 Nginx 5xx 最多的接口和上游，找出原因" />
              <div className={local.actions}>
                <Button type="button" variant="secondary" onClick={generate} loading={generating} disabled={!idea.trim()}>生成提示词</Button>
              </div>
            </div>
          )}
          <Input label="名称" value={name} onChange={e => setName(e.target.value)} readOnly={readOnly} required maxLength={64} />
          <Input label="描述" value={description} onChange={e => setDescription(e.target.value)} readOnly={readOnly} maxLength={200} />
          <Textarea label="提示词" value={body} onChange={e => setBody(e.target.value)} readOnly={readOnly} rows={10} maxLength={8000} required />
          {error && <Alert tone="danger" title="出错了">{error}</Alert>}
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={onClose}>{readOnly ? "关闭" : "取消"}</Button>
            {!readOnly && <Button type="submit" loading={saving}>保存</Button>}
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
