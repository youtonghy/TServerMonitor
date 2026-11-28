// nginx config files & editor in a large dialog (opened from the nginx page, deep link /nginx?files=<path>).
import { useMemo, useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { Select } from "@/components/arc/select/select";
import { Switch } from "@/components/arc/switch/switch";
import { api } from "@/api/client";
import type { NginxFileEntry, NginxSite, OpsCapabilities } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { OpsJobLog } from "@/components/job-log";
import { NginxFileEditor } from "@/components/nginx-file-editor";
import { JobResult, OpsNotice, can, diffOf, type useOpsAction } from "@/components/ops";
import { Panel, Section } from "@/components/panel";
import { formatBytes } from "@/lib/format";
import pageStyles from "@/pages/pages.module.css";
import local from "@/pages/settings.module.css";
import siteStyles from "./nginx-site.module.css";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  caps: OpsCapabilities | undefined;
  sites: NginxSite[];
  /** Selected file (null = none). */
  path: string | null;
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  refreshKey: number;
  onSelectPath: (path: string | null) => void;
  onReloadSites: () => void;
}

export function NginxFilesDialog({ open, onOpenChange, ...props }: Props) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="配置文件"
        description="查看与编辑手动站点、snippets 及全局配置；保存前执行 nginx -t，失败自动恢复。证书、私钥与密码文件不会显示。"
        className={siteStyles.filesDialog}
      >
        <FilesBody {...props} />
      </DialogContent>
    </Dialog>
  );
}

/** Site whose config file is `path` (only for site directories; snippets and global files have none). */
function siteForFile(sites: NginxSite[], path: string): NginxSite | null {
  const siteFile = /^sites-available\/[^/]+$/.test(path) || /^conf\.d\/[^/]+\.conf(\.disabled)?$/.test(path);
  if (!siteFile) return null;
  const bare = (p: string) => p.replace(/\.disabled$/, "");
  return sites.find(s => s.file === path) ?? sites.find(s => bare(s.file) === bare(path)) ?? null;
}

function FilesBody({ caps, sites, path, allowEdit, ops, refreshKey, onSelectPath, onReloadSites }: Omit<Props, "open" | "onOpenChange">) {
  const files = useQuery(() => api.opsRead<NginxFileEntry[]>("nginx.files"), [refreshKey]);
  const [creating, setCreating] = useState(false);
  const [newFile, setNewFile] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const allowSite = can(caps, "nginx", "site");

  const q = filter.trim().toLowerCase();
  const list = useMemo(() => {
    const all = files.data?.data ?? [];
    if (!q) return all;
    return all.filter(f => f.path.toLowerCase().includes(q));
  }, [files.data, q]);
  const editableFiles = list.filter(f => f.editable);
  const readonlyFiles = list.filter(f => !f.editable);

  const pickFile = (p: string) => {
    setNewFile(null);
    onSelectPath(p);
  };

  // Applied right away: the helper runs nginx -t and reloads, and restores the file on failure.
  const toggleSite = async (site: NginxSite, enabled: boolean) => {
    const j = await ops.run("nginx.site", { name: site.name, enabled });
    if (j?.status === "succeeded" && !j.dry_run) {
      // conf.d sites are disabled by renaming to .conf.disabled: keep the open file selected.
      const bare = site.file.replace(/\.disabled$/, "");
      if (site.layout === "conf_d" && path?.replace(/\.disabled$/, "") === bare) onSelectPath(enabled ? bare : `${bare}.disabled`);
      files.reload();
      onReloadSites();
    }
  };

  const renderGroup = (label: string, items: NginxFileEntry[]) => {
    if (items.length === 0) return null;
    return (
      <div className={siteStyles.fileGroup}>
        <p className={siteStyles.fileGroupLabel}>{label}</p>
        <ul className={pageStyles.pickList}>
          {items.map(f => {
            const site = siteForFile(sites, f.path);
            return (
              <li key={f.path} className={site ? siteStyles.fileRow : undefined}>
                <button
                  type="button"
                  className={pageStyles.pick}
                  aria-current={!newFile && f.path === path ? "true" : undefined}
                  onClick={() => pickFile(f.path)}
                >
                  <span className={pageStyles.between}>
                    <code className={pageStyles.code}>{f.path}</code>
                    {f.editable && allowEdit && <Badge size="sm" tone="neutral" outline>可编辑</Badge>}
                  </span>
                  <span className={`${pageStyles.muted} ${pageStyles.small}`}>{formatBytes(f.size)}</span>
                </button>
                {site && (
                  <Switch
                    label="启用"
                    aria-label={`${site.enabled ? "停用" : "启用"}站点 ${site.name}`}
                    checked={site.enabled}
                    disabled={!allowSite || ops.busy !== null}
                    onCheckedChange={v => void toggleSite(site, v)}
                  />
                )}
              </li>
            );
          })}
        </ul>
      </div>
    );
  };

  return (
    <div className={siteStyles.filesBody}>
      <OpsNotice caps={caps} domain="nginx" source={files.data?.source} />
      {ops.error && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}
      {ops.job?.status === "running"
        ? <OpsJobLog id={ops.job.id} />
        : ops.job && !(ops.job.dry_run && diffOf(ops.job)) && (
          <Panel title="最近一次操作"><JobResult job={ops.job} onDismiss={() => ops.setJob(null)} /></Panel>
        )}

      <div className={pageStyles.masterDetail}>
        <Section
          title="文件"
          description="站点目录与片段可编辑；全局配置仅查看。站点文件可直接启用或停用。"
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
        ) : path ? (
          <NginxFileEditor
            key={path}
            path={path}
            allowEdit={allowEdit}
            ops={ops}
            refreshKey={refreshKey}
            managed={sites.some(s => s.file === path && s.managed)}
            onSaved={() => {
              files.reload();
              onReloadSites();
            }}
          />
        ) : (
          <Panel title="编辑器">
            <p className={pageStyles.textSecondary}>
              从左侧选择一个文件查看{allowEdit ? "、编辑或让代理撰写配置" : ""}。
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
    </div>
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
