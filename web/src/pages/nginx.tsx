import { lazy, Suspense, useEffect, useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { Skeleton } from "@/components/arc/skeleton/skeleton";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { api } from "@/api/client";
import type { NginxFile, NginxFileEntry, NginxSites, OpsJob } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { JobResult, OpsNotice, can, diffOf, useOpsAction, useOpsCaps } from "@/components/ops";
import { PageHeader, Panel, Section, errorMessage } from "@/components/panel";
import { formatBytes } from "@/lib/format";
import { findingSeverityLabel, findingSeverityTone } from "@/lib/labels";
import opsStyles from "@/components/ops.module.css";
import styles from "./pages.module.css";
import local from "./settings.module.css";

const CodeEditor = lazy(() => import("@/components/code-editor"));

type SiteRow = { name: string; names: string; listen: string; ssl: boolean; enabled: boolean; file: string };

/** A file being edited: `base` is the sha256 it was read with (null = new file). */
interface Editing { path: string; base: string | null; original: string; draft: string; editable: boolean }

export default function NginxPage() {
  const caps = useOpsCaps();
  const sites = useQuery(() => api.opsRead<NginxSites>("nginx.sites"), []);
  const files = useQuery(() => api.opsRead<NginxFileEntry[]>("nginx.files"), []);
  const findings = useQuery(() => api.findings(), []);
  const ops = useOpsAction();
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newFile, setNewFile] = useState<string | null>(null);
  const [toggle, setToggle] = useState<SiteRow | null>(null);

  const c = caps.data;
  const allowSite = can(c, "nginx", "site");
  const allowEdit = can(c, "nginx", "edit");

  const afterChange = (j: OpsJob | null) => {
    if (j?.status === "succeeded" && !j.dry_run) {
      sites.reload();
      files.reload();
    }
  };

  const columns: DataColumn<SiteRow>[] = [
    { key: "name", label: "站点", sortable: true, render: (_v, r) => <span className={styles.row}><code className={styles.code}>{r.name}</code>{r.ssl && <Badge size="sm" tone="info">TLS</Badge>}</span> },
    { key: "names", label: "域名", render: (_v, r) => <span className={styles.small}>{r.names || "—"}</span> },
    { key: "listen", label: "监听", render: (_v, r) => <span className={`${styles.small} ${styles.muted}`}>{r.listen}</span> },
    { key: "enabled", label: "状态", sortable: true, render: (_v, r) => <Badge size="sm" tone={r.enabled ? "success" : "neutral"} dot>{r.enabled ? "已启用" : "已停用"}</Badge> },
    {
      key: "file", label: "", render: (_v, r) => (
        <span className={local.rowActions}>
          <Button size="sm" variant="ghost" onClick={() => setSelected(r.file)}>查看配置</Button>
          {allowSite && <Button size="sm" variant="ghost" onClick={() => setToggle(r)}>{r.enabled ? "停用" : "启用"}</Button>}
        </span>
      ),
    },
  ];

  const nginxFindings = (findings.data ?? []).filter(f => f.category === "nginx" || f.category === "perf");

  return (
    <>
      <PageHeader title="nginx" description="站点、配置文件与优化建议；修改经运维助手执行，失败时自动恢复原配置">
        {can(c, "nginx", "test") && <Button variant="secondary" loading={ops.busy === "nginx.test"} onClick={() => ops.run("nginx.test")}>检查配置</Button>}
        {can(c, "nginx", "reload") && <Button loading={ops.busy === "nginx.reload"} onClick={() => ops.run("nginx.reload")}>重新加载</Button>}
      </PageHeader>

      <OpsNotice caps={c} domain="nginx" source={sites.data?.source} />
      {ops.error && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}
      {ops.job && !(ops.job.dry_run && diffOf(ops.job)) && <Panel title="最近一次操作"><JobResult job={ops.job} onDismiss={() => ops.setJob(null)} /></Panel>}

      <Section
        title="站点"
        description={sites.data ? (sites.data.data.layout === "sites_enabled" ? "sites-available / sites-enabled 布局" : "conf.d 布局（停用 = 改名为 .conf.disabled）") : undefined}
        query={sites}
        flush
        isEmpty={d => d.data.sites.length === 0}
        empty={{ title: "没有发现站点", description: "未找到 sites-available 或含 server 块的 conf.d 文件。" }}
      >
        {d => (
          <SortableDataTable<SiteRow>
            rows={d.data.sites.map(s => ({ name: s.name, names: s.server_names.join(" "), listen: s.listen.join("，"), ssl: s.ssl, enabled: s.enabled, file: s.file }))}
            columns={columns}
            rowKey="name"
            caption="nginx 站点"
          />
        )}
      </Section>

      <div className={styles.masterDetail}>
        <Section
          title="配置文件"
          actions={allowEdit && <Button size="sm" variant="secondary" onClick={() => setCreating(true)}>新建</Button>}
          query={files}
          isEmpty={d => d.data.length === 0}
          empty={{ title: "没有配置文件", description: "守护进程或运维助手读不到 nginx 配置目录。" }}
        >
          {d => (
            <ul className={styles.pickList}>
              {d.data.map(f => (
                <li key={f.path}>
                  <button type="button" className={styles.pick} aria-current={f.path === selected ? "true" : undefined} onClick={() => { setNewFile(null); setSelected(f.path); }}>
                    <span className={styles.between}>
                      <code className={styles.code}>{f.path}</code>
                      {f.editable && allowEdit && <Badge size="sm" tone="neutral" outline>可编辑</Badge>}
                    </span>
                    <span className={`${styles.muted} ${styles.small}`}>{formatBytes(f.size)}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Section>
        {newFile
          ? <FileEditor key={`new:${newFile}`} path={newFile} isNew allowEdit={allowEdit} ops={ops} onSaved={() => { setSelected(newFile); setNewFile(null); files.reload(); sites.reload(); }} />
          : selected
            ? <FileEditor key={selected} path={selected} allowEdit={allowEdit} ops={ops} onSaved={() => { files.reload(); sites.reload(); }} />
            : <Panel title="编辑器"><p className={styles.textSecondary}>从左侧选择一个文件查看{allowEdit ? "或编辑" : ""}。证书、私钥与密码文件不会显示。</p></Panel>}
      </div>

      <Section
        title="优化与加固建议"
        description="根据 nginx 配置和最近一小时的访问统计生成，每次安全巡检时刷新"
        query={findings}
        isEmpty={() => nginxFindings.length === 0}
        empty={{ title: "暂无建议", description: "配置与访问统计没有发现明显问题（或尚未完成首次巡检）。" }}
      >
        {() => (
          <ul className={styles.list}>
            {nginxFindings.map(f => (
              <li key={f.id} className={local.providerRow}>
                <div className={local.providerMain}>
                  <span className={styles.row}>
                    <Badge size="sm" tone={findingSeverityTone[f.severity]}>{findingSeverityLabel[f.severity]}</Badge>
                    <span className={styles.strong}>{f.title}</span>
                  </span>
                  <p className={styles.textSecondary}>{f.detail}</p>
                  {f.evidence && <code className={`${styles.code} ${styles.muted}`}>{f.evidence}</code>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <ConfirmDialog
        open={toggle !== null}
        onOpenChange={o => { if (!o) setToggle(null); }}
        title={toggle?.enabled ? `停用站点 ${toggle.name}？` : `启用站点 ${toggle?.name ?? ""}？`}
        description="运维助手会先执行 nginx -t，通过后重新加载；失败会自动恢复。"
        danger={toggle?.enabled}
        confirmLabel={toggle?.enabled ? "停用" : "启用"}
        onConfirm={async () => { if (toggle) afterChange(await ops.run("nginx.site", { name: toggle.name, enabled: !toggle.enabled })); }}
      />
      <NewFileDialog open={creating} onOpenChange={setCreating} onCreate={p => { setNewFile(p); setSelected(null); }} />
    </>
  );
}

function NewFileDialog({ open, onOpenChange, onCreate }: { open: boolean; onOpenChange: (o: boolean) => void; onCreate: (path: string) => void }) {
  const [dir, setDir] = useState("sites-available");
  const [name, setName] = useState("");
  const valid = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(name) && (dir === "sites-available" || name.endsWith(".conf"));
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    onCreate(`${dir}/${name}`);
    setName("");
    onOpenChange(false);
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="新建配置文件" description="保存前会执行 nginx -t；新文件未通过检查时会被删除。">
        <form className={local.form} onSubmit={submit}>
          <Select label="目录" value={dir} onValueChange={setDir} options={[{ value: "sites-available", label: "sites-available" }, { value: "conf.d", label: "conf.d" }, { value: "snippets", label: "snippets" }]} />
          <Input label="文件名" value={name} onChange={e => setName(e.target.value)} description={dir === "sites-available" ? "例如 shop" : "必须以 .conf 结尾"} required maxLength={128} />
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
            <Button type="submit" disabled={!valid}>开始编辑</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface FileEditorProps {
  path: string;
  isNew?: boolean;
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  onSaved: () => void;
}

function FileEditor({ path, isNew, allowEdit, ops, onSaved }: FileEditorProps) {
  const file = useQuery(() => (isNew ? Promise.resolve(null) : api.opsRead<NginxFile>("nginx.file", { path })), [path, isNew]);
  const [edit, setEdit] = useState<Editing | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    if (isNew) {
      setEdit({ path, base: null, original: "", draft: "server {\n    listen 80;\n    server_name example.com;\n}\n", editable: true });
    } else if (file.data) {
      const f = file.data.data;
      setEdit({ path, base: f.sha256, original: f.content, draft: f.content, editable: f.editable });
    } else if (file.status === "error") {
      setLoadError(errorMessage(file.error));
    }
  }, [file.data, file.status, file.error, isNew, path]);

  if (loadError) return <Panel title={path}><Alert tone="danger" title="无法读取">{loadError}</Alert></Panel>;
  if (!edit) return <Panel title={path}><Skeleton lines={10} label="正在读取" /></Panel>;

  const canWrite = allowEdit && edit.editable;
  const dirty = edit.draft !== edit.original || isNew;
  const args = { path, content: edit.draft, base_sha256: edit.base };

  const review = async () => {
    const j = await ops.run("nginx.write", args, true);
    const d = diffOf(j);
    if (j?.status === "succeeded") setPreview(d ?? "");
  };
  const save = async () => {
    const j = await ops.run("nginx.write", args, false);
    if (j?.status === "succeeded") {
      const sha = typeof j.result?.sha256 === "string" ? j.result.sha256 : edit.base;
      setEdit({ ...edit, base: sha, original: edit.draft });
      onSaved();
    }
  };

  return (
    <Panel
      title={path}
      description={canWrite ? (isNew ? "新文件" : dirty ? "有未保存的修改" : "与服务器上的文件一致") : "只读"}
      actions={canWrite && (
        <span className={local.rowActions}>
          {!isNew && <Button size="sm" variant="ghost" disabled={!dirty} onClick={() => setEdit({ ...edit, draft: edit.original })}>放弃修改</Button>}
          <Button size="sm" disabled={!dirty} loading={ops.busy === "nginx.write"} onClick={review}>预览并保存</Button>
        </span>
      )}
    >
      <Suspense fallback={<Skeleton lines={10} label="正在加载编辑器" />}>
        <CodeEditor key={`${path}:${canWrite}`} value={edit.draft} onChange={draft => setEdit(e => e && { ...e, draft })} readOnly={!canWrite} label={`编辑 ${path}`} />
      </Suspense>
      {!canWrite && !edit.editable && <p className={opsStyles.muted}>这个文件不在可编辑目录中（helper.toml 的 nginx.edit_dirs）。</p>}
      <ConfirmDialog
        open={preview !== null}
        onOpenChange={o => { if (!o) setPreview(null); }}
        title={`保存 ${path}？`}
        description="保存后会执行 nginx -t 并重新加载；检查、重载或探测失败时自动恢复原文件。"
        confirmLabel="保存并重新加载"
        wide
        onConfirm={save}
      >
        {preview ? <CodeBlock code={preview} language="diff" filename={`${path}.diff`} maxLines={24} /> : <p className={opsStyles.muted}>内容没有变化。</p>}
      </ConfirmDialog>
    </Panel>
  );
}
