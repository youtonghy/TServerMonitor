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
import { Switch } from "@/components/arc/switch/switch";
import { api } from "@/api/client";
import type { NginxFile, NginxFileEntry, NginxSite, NginxSiteDetail, NginxSites, OpsCapabilities, OpsJob, SiteSpec } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { OpsJobLog } from "@/components/job-log";
import { CertDialog } from "@/components/nginx-cert-dialog";
import { SiteDrawer } from "@/components/nginx-site-drawer";
import { JobResult, OpsNotice, can, diffOf, useOpsAction, useOpsCaps } from "@/components/ops";
import { PageHeader, Panel, Section, errorMessage, useNow } from "@/components/panel";
import { formatBytes } from "@/lib/format";
import { findingSeverityLabel, findingSeverityTone } from "@/lib/labels";
import { certStatus, covers, siteKindLabel } from "@/lib/nginx-site";
import opsStyles from "@/components/ops.module.css";
import siteStyles from "@/components/nginx-site.module.css";
import styles from "./pages.module.css";
import local from "./settings.module.css";

const CodeEditor = lazy(() => import("@/components/code-editor"));

type SiteRow = { [K in keyof NginxSite]: NginxSite[K] } & { names: string };

/** A file being edited: `base` is the sha256 it was read with (null = new file). */
interface Editing { path: string; base: string | null; original: string; draft: string; editable: boolean }

export default function NginxPage() {
  const caps = useOpsCaps();
  const sites = useQuery(() => api.opsRead<NginxSites>("nginx.sites"), []);
  const files = useQuery(() => api.opsRead<NginxFileEntry[]>("nginx.files"), []);
  const findings = useQuery(() => api.findings(), []);
  const ops = useOpsAction();
  const now = useNow();
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newFile, setNewFile] = useState<string | null>(null);
  const [toggle, setToggle] = useState<SiteRow | null>(null);
  const [form, setForm] = useState<{ detail: NginxSiteDetail | null } | null>(null);
  const [remove, setRemove] = useState<SiteRow | null>(null);
  const [purge, setPurge] = useState(false);
  const [certFor, setCertFor] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const c = caps.data;
  const nginxCaps = c?.domains.nginx;
  const allowSite = can(c, "nginx", "site");
  const allowEdit = can(c, "nginx", "edit");
  const allowManage = can(c, "nginx", "manage");
  const allowCert = can(c, "nginx", "cert");
  const siteList = sites.data?.data.sites ?? [];
  const certSite = siteList.find(s => s.file === certFor) ?? null;

  const afterChange = (j: OpsJob | null) => {
    if (j?.status === "succeeded" && !j.dry_run) {
      sites.reload();
      files.reload();
    }
  };

  const openEdit = async (r: SiteRow) => {
    setLoadError(null);
    try {
      const d = await api.opsRead<NginxSiteDetail>("nginx.site_get", { name: r.name });
      setForm({ detail: d.data });
    } catch (e) {
      setLoadError(errorMessage(e instanceof Error ? e : new Error(String(e))));
    }
  };

  // After a save: issue the certificate right away (ACME), or ask for the upload.
  const onSaved = async (spec: SiteSpec, j: OpsJob) => {
    files.reload();
    let fresh: NginxSites["sites"] = [];
    try {
      const r = await api.opsRead<NginxSites>("nginx.sites");
      sites.setData(() => r);
      fresh = r.data.sites;
    } catch {
      sites.reload();
    }
    if (j.dry_run) return;
    const site = fresh.find(s => s.name === spec.name && s.managed);
    const c = site?.cert;
    // no certificate yet, or domains were added that it does not cover
    const missing = c && (c.not_after === null || spec.domains.some(d => !c.names.some(n => covers(n, d))));
    if (!missing || !site) return;
    if (spec.ssl.mode === "acme" && site.enabled) {
      afterChange(await ops.run("nginx.cert_issue", { name: spec.name }, false, { follow: true }));
    } else if (spec.ssl.mode === "upload") {
      setCertFor(site.file);
    }
  };

  const columns: DataColumn<SiteRow>[] = [
    {
      key: "name", label: "站点", sortable: true, render: (_v, r) => (
        <span className={styles.row}>
          <code className={styles.code}>{r.name}</code>
          {r.managed ? <Badge size="sm" tone="info">{siteKindLabel[r.kind ?? "proxy"]}</Badge> : <Badge size="sm" tone="neutral" outline>手动</Badge>}
          {r.drifted && <Badge size="sm" tone="warning">已手动修改</Badge>}
          {!r.managed && r.ssl && <Badge size="sm" tone="neutral">TLS</Badge>}
        </span>
      ),
    },
    { key: "names", label: "域名", render: (_v, r) => <span className={styles.small}>{r.names || "—"}</span> },
    {
      key: "ssl", label: "证书", render: (_v, r) => {
        if (!r.managed) return <span className={`${styles.small} ${styles.muted}`}>{r.ssl ? "手动配置" : "—"}</span>;
        const st = certStatus(r.cert, now);
        return <span title={st.detail}><Badge size="sm" tone={st.tone} dot>{st.label}</Badge></span>;
      },
    },
    {
      key: "enabled", label: "启用", sortable: true, render: (_v, r) => allowSite
        ? <Switch aria-label={`${r.enabled ? "停用" : "启用"}站点 ${r.name}`} checked={r.enabled} onCheckedChange={() => setToggle(r)} />
        : <Badge size="sm" tone={r.enabled ? "success" : "neutral"} dot>{r.enabled ? "已启用" : "已停用"}</Badge>,
    },
    {
      key: "file", label: "", render: (_v, r) => (
        <span className={siteStyles.siteActions}>
          {r.managed && allowManage && <Button size="sm" variant="ghost" onClick={() => openEdit(r)}>编辑</Button>}
          {r.managed && r.cert && r.cert.mode !== "none" && <Button size="sm" variant="ghost" onClick={() => setCertFor(r.file)}>证书</Button>}
          <Button size="sm" variant="ghost" onClick={() => setSelected(r.file)}>配置文件</Button>
          {r.managed && allowManage && <Button size="sm" variant="ghost" onClick={() => { setPurge(false); setRemove(r); }}>删除</Button>}
        </span>
      ),
    },
  ];

  const nginxFindings = (findings.data ?? []).filter(f => f.category === "nginx" || f.category === "perf" || f.category === "cert");

  return (
    <>
      <PageHeader title="nginx" description="按站点管理域名、反向代理、静态站点与 SSL 证书；修改经运维助手执行，失败时自动恢复原配置">
        {can(c, "nginx", "test") && <Button variant="secondary" loading={ops.busy === "nginx.test"} onClick={() => ops.run("nginx.test")}>检查配置</Button>}
        {can(c, "nginx", "reload") && <Button variant="secondary" loading={ops.busy === "nginx.reload"} onClick={() => ops.run("nginx.reload")}>重新加载</Button>}
        {allowManage && <Button onClick={() => { ops.setError(null); setForm({ detail: null }); }}>新建站点</Button>}
      </PageHeader>

      <OpsNotice caps={c} domain="nginx" source={sites.data?.source} />
      <SetupHint caps={c} />
      {loadError && <Alert tone="danger" title="无法读取站点设置" onDismiss={() => setLoadError(null)}>{loadError}</Alert>}
      {ops.error && !form && !certSite && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}
      {ops.job?.status === "running"
        ? <OpsJobLog id={ops.job.id} />
        : ops.job && !(ops.job.dry_run && diffOf(ops.job)) && !form && <Panel title="最近一次操作"><JobResult job={ops.job} onDismiss={() => ops.setJob(null)} /></Panel>}

      <Section
        title="站点"
        description={sites.data ? (sites.data.data.layout === "sites_enabled" ? "sites-available / sites-enabled 布局" : "conf.d 布局（停用 = 改名为 .conf.disabled）") : undefined}
        query={sites}
        flush
        isEmpty={d => d.data.sites.length === 0}
        empty={{ title: "还没有站点", description: allowManage ? "点右上角“新建站点”，填写域名和目标地址即可创建。" : "未找到 sites-available 或含 server 块的 conf.d 文件。" }}
      >
        {d => (
          <SortableDataTable<SiteRow>
            rows={d.data.sites.map(s => ({ ...s, names: s.server_names.join(" ") }))}
            columns={columns}
            rowKey="file"
            caption="nginx 站点"
          />
        )}
      </Section>

      <div className={styles.masterDetail}>
        <Section
          title="配置文件（高级）"
          description="手动维护的站点和全局配置在这里直接编辑；面板生成的站点请用“编辑”"
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
            ? <FileEditor key={selected} path={selected} allowEdit={allowEdit} ops={ops} managed={siteList.some(s => s.file === selected && s.managed)} onSaved={() => { files.reload(); sites.reload(); }} />
            : <Panel title="编辑器"><p className={styles.textSecondary}>从左侧选择一个文件查看{allowEdit ? "或编辑" : ""}。证书、私钥与密码文件不会显示。</p></Panel>}
      </div>

      <Section
        title="优化、加固与证书提醒"
        description="根据 nginx 配置、站点证书和最近一小时的访问统计生成，每次安全巡检时刷新"
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
      <ConfirmDialog
        open={remove !== null}
        onOpenChange={o => { if (!o) setRemove(null); }}
        title={`删除站点 ${remove?.name ?? ""}？`}
        description="删除配置文件和站点设置后执行 nginx -t 并重新加载；失败会自动恢复。备份只保留最近 50 份，删除后请勿依赖恢复。"
        danger
        confirmLabel="删除站点"
        requireText={remove?.name}
        onConfirm={async () => { if (remove) afterChange(await ops.run("nginx.site_delete", { name: remove.name, purge_certs: purge })); }}
      >
        {remove?.cert && remove.cert.mode !== "none" && <Switch label="同时删除此站点的证书文件" checked={purge} onCheckedChange={setPurge} />}
      </ConfirmDialog>
      <SiteDrawer
        open={form !== null}
        onOpenChange={o => { if (!o) setForm(null); }}
        detail={form?.detail ?? null}
        caps={nginxCaps}
        allowCert={allowCert}
        allowEdit={allowEdit}
        ops={ops}
        onSaved={onSaved}
      />
      <CertDialog site={certSite} onOpenChange={o => { if (!o) setCertFor(null); }} caps={nginxCaps} ops={ops} onDone={afterChange} />
      <NewFileDialog open={creating} onOpenChange={setCreating} onCreate={p => { setNewFile(p); setSelected(null); }} />
    </>
  );
}

/** Shown when the helper manages nginx but form sites or certificates are not allowed yet. */
function SetupHint({ caps }: { caps: OpsCapabilities | undefined }) {
  const n = caps?.domains.nginx;
  if (!caps?.write_ready || !n?.enabled) return null;
  const missing = ["manage", "cert"].filter(op => !n.allow.includes(op));
  const acmeOff = n.allow.includes("cert") && n.acme && !n.acme.enabled;
  if (missing.length === 0 && !acmeOff) return null;
  const allow = [...new Set([...n.allow, ...missing])].map(a => `"${a}"`).join(", ");
  const snippet = `[nginx]\nenabled = true\nallow = [${allow}]\n\n[nginx.acme]\nenabled = true\n# email = "ops@example.com"`;
  return (
    <Alert tone="info" title={missing.includes("manage") ? "开启表单建站与证书管理" : "开启自动申请证书"}>
      <p className={styles.textSecondary}>
        出于安全考虑，权限只能在服务器上修改。把下面的内容合并到 /etc/tsmonitor/helper.toml，然后执行 systemctl restart tsmonitor-helper。
      </p>
      <CodeBlock code={snippet} language="toml" filename="helper.toml" maxLines={10} />
    </Alert>
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
  /** Generated from the site form: hand edits are overwritten by the next form save. */
  managed?: boolean;
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  onSaved: () => void;
}

function FileEditor({ path, isNew, managed, allowEdit, ops, onSaved }: FileEditorProps) {
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
      {managed && canWrite && <Alert tone="warning" title="这是面板生成的站点">建议在站点列表中点“编辑”修改；在这里手动修改后，下次用表单保存时需要确认覆盖。</Alert>}
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
