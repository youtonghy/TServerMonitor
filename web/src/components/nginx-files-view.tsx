// Standalone nginx config files & editor view (/nginx/files).
import { useMemo, useState, type FormEvent } from "react";
import { ArrowLeft } from "lucide-react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { api } from "@/api/client";
import type { NginxFileEntry, NginxSite, OpsCapabilities } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { OpsJobLog } from "@/components/job-log";
import { NginxFileEditor } from "@/components/nginx-file-editor";
import { JobResult, OpsNotice, can, diffOf, type useOpsAction } from "@/components/ops";
import { PageHeader, Panel, Section } from "@/components/panel";
import { formatBytes } from "@/lib/format";
import pageStyles from "@/pages/pages.module.css";
import local from "@/pages/settings.module.css";
import siteStyles from "./nginx-site.module.css";

interface Props {
  caps: OpsCapabilities | undefined;
  sites: NginxSite[];
  initialPath: string | null;
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  refreshKey: number;
  onBack: () => void;
  onSelectPath: (path: string | null) => void;
  onReloadSites: () => void;
}

export function NginxFilesView({
  caps,
  sites,
  initialPath,
  allowEdit,
  ops,
  refreshKey,
  onBack,
  onSelectPath,
  onReloadSites,
}: Props) {
  const files = useQuery(() => api.opsRead<NginxFileEntry[]>("nginx.files"), [refreshKey]);
  const [creating, setCreating] = useState(false);
  const [newFile, setNewFile] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const q = filter.trim().toLowerCase();
  const list = useMemo(() => {
    const all = files.data?.data ?? [];
    if (!q) return all;
    return all.filter(f => f.path.toLowerCase().includes(q));
  }, [files.data, q]);
  const editableFiles = list.filter(f => f.editable);
  const readonlyFiles = list.filter(f => !f.editable);

  const pickFile = (path: string) => {
    setNewFile(null);
    onSelectPath(path);
  };

  const renderGroup = (label: string, items: NginxFileEntry[]) => {
    if (items.length === 0) return null;
    return (
      <div className={siteStyles.fileGroup}>
        <p className={siteStyles.fileGroupLabel}>{label}</p>
        <ul className={pageStyles.pickList}>
          {items.map(f => (
            <li key={f.path}>
              <button
                type="button"
                className={pageStyles.pick}
                aria-current={!newFile && f.path === initialPath ? "true" : undefined}
                onClick={() => pickFile(f.path)}
              >
                <span className={pageStyles.between}>
                  <code className={pageStyles.code}>{f.path}</code>
                  {f.editable && allowEdit && <Badge size="sm" tone="neutral" outline>可编辑</Badge>}
                </span>
                <span className={`${pageStyles.muted} ${pageStyles.small}`}>{formatBytes(f.size)}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    );
  };

  return (
    <>
      <PageHeader title="nginx 配置文件" description="独立查看与编辑手动站点、snippets 及全局配置；修改经运维助手执行，支持由代理撰写内容">
        <Button variant="ghost" onClick={onBack}>
          <ArrowLeft size={15} strokeWidth={1.75} aria-hidden="true" />
          <span>返回站点</span>
        </Button>
        {can(caps, "nginx", "test") && (
          <Button variant="secondary" loading={ops.busy === "nginx.test"} onClick={() => ops.run("nginx.test")}>检查配置</Button>
        )}
        {can(caps, "nginx", "reload") && (
          <Button variant="secondary" loading={ops.busy === "nginx.reload"} onClick={() => ops.run("nginx.reload")}>重新加载</Button>
        )}
        {allowEdit && <Button onClick={() => setCreating(true)}>新建文件</Button>}
      </PageHeader>

      <OpsNotice caps={caps} domain="nginx" source={files.data?.source} />
      {ops.error && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}
      {ops.job?.status === "running"
        ? <OpsJobLog id={ops.job.id} />
        : ops.job && !(ops.job.dry_run && diffOf(ops.job)) && (
          <Panel title="最近一次操作"><JobResult job={ops.job} onDismiss={() => ops.setJob(null)} /></Panel>
        )}

      <div className={pageStyles.masterDetail}>
        <Section
          title="配置文件"
          description="站点目录与片段可编辑；全局配置仅查看。证书、私钥与密码文件不会显示。"
          actions={allowEdit && <Button size="sm" variant="secondary" onClick={() => setCreating(true)}>新建</Button>}
          query={files}
          isEmpty={d => d.data.length === 0}
          empty={{ title: "没有配置文件", description: "守护进程或运维助手读不到 nginx 配置目录。" }}
        >
          {d => (
            <div className={siteStyles.fileGroups}>
              {d.data.length > 5 && (
                <Input
                  label="筛选文件"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  placeholder="输入路径关键词，例如 sites-available"
                />
              )}
              {list.length === 0
                ? <p className={pageStyles.textSecondary}>没有匹配「{filter}」的配置文件。</p>
                : (
                  <>
                    {renderGroup("可编辑配置", editableFiles)}
                    {renderGroup("只读与全局配置", readonlyFiles)}
                  </>
                )}
            </div>
          )}
        </Section>

        {newFile ? (
          <NginxFileEditor
            key={`new:${newFile}`}
            path={newFile}
            isNew
            allowEdit={allowEdit}
            ops={ops}
            refreshKey={refreshKey}
            onSaved={() => {
              const saved = newFile;
              setNewFile(null);
              onSelectPath(saved);
              files.reload();
              onReloadSites();
            }}
          />
        ) : initialPath ? (
          <NginxFileEditor
            key={initialPath}
            path={initialPath}
            allowEdit={allowEdit}
            ops={ops}
            refreshKey={refreshKey}
            managed={sites.some(s => s.file === initialPath && s.managed)}
            onSaved={() => {
              files.reload();
              onReloadSites();
            }}
          />
        ) : (
          <Panel title="编辑器">
            <p className={pageStyles.textSecondary}>
              从左侧选择一个文件查看{allowEdit ? "、编辑或让代理撰写配置" : ""}。证书、私钥与密码文件不会显示。
            </p>
          </Panel>
        )}
      </div>

      <NewFileDialog
        open={creating}
        onOpenChange={setCreating}
        onCreate={p => {
          setNewFile(p);
          onSelectPath(null);
        }}
      />
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
          <Select
            label="目录"
            value={dir}
            onValueChange={setDir}
            options={[
              { value: "sites-available", label: "sites-available" },
              { value: "conf.d", label: "conf.d" },
              { value: "snippets", label: "snippets" },
            ]}
          />
          <Input
            label="文件名"
            value={name}
            onChange={e => setName(e.target.value)}
            description={dir === "sites-available" ? "例如 shop" : "必须以 .conf 结尾"}
            required
            maxLength={128}
          />
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
            <Button type="submit" disabled={!valid}>开始编辑</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
