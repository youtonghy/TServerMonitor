// Docker management: lifecycle of existing containers, compose projects, images, volumes and
// networks, through the ops helper. No exec and no container creation by design.
import { useState, type FormEvent, type ReactNode } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { api } from "@/api/client";
import type { DockerImage, DockerInventory, DockerNetwork, DockerVolume } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { formatBytes, formatDateTime } from "@/lib/format";
import { ConfirmDialog } from "./confirm-dialog";
import { OpsJobLog } from "./job-log";
import { JobResult, OpsNotice, can, useOpsAction, useOpsCaps } from "./ops";
import { PageHeader, Panel, Section } from "./panel";
import styles from "@/pages/pages.module.css";
import local from "@/pages/settings.module.css";

type Action = "start" | "stop" | "restart" | "kill" | "remove";
const ACTION_LABEL: Record<Action, string> = { start: "启动", stop: "停止", restart: "重启", kill: "强制终止", remove: "删除" };
const DESTRUCTIVE: Action[] = ["kill", "remove"];

interface Pending { title: string; description: string; call: string; args: Record<string, unknown>; danger?: boolean; requireText?: string }

type CRow = { id: string; name: string; image: string; state: string; status: string; project: string; protected: boolean };
type IRow = { id: string; tags: string; size: number; created: number; containers: number; dangling: boolean };
type VRow = DockerVolume & Record<string, unknown>;
type NRow = DockerNetwork & Record<string, unknown>;

export function DockerManage({ tabs }: { tabs: ReactNode }) {
  const caps = useOpsCaps();
  const [view, setView] = useState("containers");
  const inv = useQuery(() => api.opsRead<DockerInventory>("docker.containers"), []);
  const images = useQuery(() => api.opsRead<DockerImage[]>("docker.images"), []);
  const volumes = useQuery(() => api.opsRead<DockerVolume[]>("docker.volumes"), []);
  const networks = useQuery(() => api.opsRead<DockerNetwork[]>("docker.networks"), []);
  const ops = useOpsAction();
  const [confirm, setConfirm] = useState<Pending | null>(null);
  const [pulling, setPulling] = useState(false);
  const c = caps.data;

  const run = async (p: Pending) => {
    const j = await ops.run(p.call, p.args);
    if (j && j.status !== "running") {
      inv.reload();
      images.reload();
      volumes.reload();
    }
  };

  const ask = (a: Action, row: CRow) => setConfirm({
    title: `${ACTION_LABEL[a]}容器 ${row.name}？`,
    description: a === "remove" ? "容器会被删除（数据卷保留）。运行中的容器需要先停止。" : a === "kill" ? "立即发送 SIGKILL，进程没有机会正常退出。" : `将${ACTION_LABEL[a]} ${row.name}。`,
    call: "docker.container",
    args: { id: row.id, action: a },
    danger: DESTRUCTIVE.includes(a) || a === "stop",
    requireText: DESTRUCTIVE.includes(a) ? row.name : undefined,
  });

  const containerColumns: DataColumn<CRow>[] = [
    { key: "name", label: "名称", sortable: true, render: (_v, r) => <span className={styles.row}><span className={styles.strong}>{r.name}</span>{r.protected && <Badge size="sm" tone="neutral" outline>受保护</Badge>}</span> },
    { key: "image", label: "镜像", render: (_v, r) => <code className={`${styles.code} ${styles.muted}`}>{r.image}</code> },
    { key: "project", label: "项目", sortable: true },
    { key: "state", label: "状态", sortable: true, render: (_v, r) => <span className={styles.row}><Badge size="sm" tone={r.state === "running" ? "success" : r.state === "exited" ? "neutral" : "warning"} dot>{r.state}</Badge><span className={`${styles.small} ${styles.muted}`}>{r.status}</span></span> },
    {
      key: "id", label: "", render: (_v, r) => {
        const acts: Action[] = r.state === "running" ? ["restart", "stop", "kill"] : ["start", "remove"];
        const allowed = acts.filter(a => can(c, "docker", a) && (!r.protected || a === "start"));
        return <span className={local.rowActions}>{allowed.map(a => <Button key={a} size="sm" variant={DESTRUCTIVE.includes(a) ? "danger" : "ghost"} onClick={() => ask(a, r)}>{ACTION_LABEL[a]}</Button>)}</span>;
      },
    },
  ];
  const imageColumns: DataColumn<IRow>[] = [
    { key: "tags", label: "镜像", sortable: true, render: (_v, r) => <span className={styles.row}><code className={styles.code}>{r.tags || "<none>"}</code>{r.dangling && <Badge size="sm" tone="warning">悬空</Badge>}</span> },
    { key: "id", label: "ID", render: (_v, r) => <code className={`${styles.code} ${styles.muted}`}>{r.id}</code> },
    { key: "size", label: "大小", sortable: true, numeric: true, render: (_v, r) => formatBytes(r.size) },
    { key: "created", label: "创建时间", sortable: true, render: (_v, r) => <span className={styles.small}>{formatDateTime(r.created)}</span> },
    { key: "containers", label: "使用中", numeric: true, render: (_v, r) => (r.containers < 0 ? "—" : r.containers) },
    {
      key: "dangling", label: "", render: (_v, r) => can(c, "docker", "image_remove")
        ? <Button size="sm" variant="ghost" onClick={() => setConfirm({ title: `删除镜像 ${r.tags || r.id}？`, description: "正被容器使用的镜像不会被删除。", call: "docker.image_remove", args: { id: r.tags.split(", ")[0] || r.id }, danger: true })}>删除</Button>
        : null,
    },
  ];
  const volumeColumns: DataColumn<VRow>[] = [
    { key: "name", label: "卷", sortable: true, render: (_v, r) => <code className={styles.code}>{r.name}</code> },
    { key: "driver", label: "驱动" },
    { key: "project", label: "项目", render: (_v, r) => r.project ?? "—" },
    { key: "in_use", label: "状态", sortable: true, render: (_v, r) => <Badge size="sm" tone={r.in_use ? "success" : "neutral"} dot>{r.in_use ? "使用中" : "未使用"}</Badge> },
    {
      key: "actions", label: "", render: (_v, r) => can(c, "docker", "volume_remove") && !r.in_use
        ? <Button size="sm" variant="danger" onClick={() => setConfirm({ title: `删除卷 ${r.name}？`, description: "卷中的数据会永久丢失。", call: "docker.volume_remove", args: { name: r.name }, danger: true, requireText: r.name })}>删除</Button>
        : null,
    },
  ];
  const networkColumns: DataColumn<NRow>[] = [
    { key: "name", label: "网络", sortable: true, render: (_v, r) => <code className={styles.code}>{r.name}</code> },
    { key: "driver", label: "驱动", sortable: true },
    { key: "scope", label: "范围" },
    { key: "internal", label: "内部", render: (_v, r) => (r.internal ? "是" : "否") },
    { key: "id", label: "ID", render: (_v, r) => <code className={`${styles.code} ${styles.muted}`}>{r.id}</code> },
  ];

  const views = [
    { value: "containers", label: "容器" }, { value: "projects", label: "Compose 项目" },
    { value: "images", label: "镜像" }, { value: "volumes", label: "卷" }, { value: "networks", label: "网络" },
  ];

  return (
    <>
      <PageHeader title="Docker" description="管理已有容器、compose 项目与镜像；不提供 exec 与新建容器">
        {tabs}
      </PageHeader>
      <OpsNotice caps={c} domain="docker" source={inv.data?.source} />
      {ops.error && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}
      {ops.job && (ops.job.status === "running"
        ? <OpsJobLog key={ops.job.id} id={ops.job.id} />
        : <Panel title="最近一次操作"><JobResult job={ops.job} onDismiss={() => ops.setJob(null)} /></Panel>)}

      <div className={styles.between}>
        <SegmentedControl label="视图" options={views} value={view} onValueChange={setView} />
        <span className={local.rowActions}>
          {view === "images" && can(c, "docker", "image_prune") && <Button size="sm" variant="secondary" onClick={() => setConfirm({ title: "清理悬空镜像？", description: "删除没有标签、也没有被容器使用的镜像。", call: "docker.image_prune", args: {} })}>清理悬空镜像</Button>}
          {view === "images" && can(c, "docker", "image_pull") && <Button size="sm" onClick={() => setPulling(true)}>拉取镜像</Button>}
          {view === "volumes" && can(c, "docker", "volume_prune") && <Button size="sm" variant="danger" onClick={() => setConfirm({ title: "清理未使用的卷？", description: "所有未被容器使用的卷都会被删除，数据永久丢失。", call: "docker.volume_prune", args: {}, danger: true, requireText: "prune" })}>清理未使用的卷</Button>}
        </span>
      </div>

      {view === "containers" && (
        <Section title="容器" description="包含已停止的容器" query={inv} flush isEmpty={d => d.data.containers.length === 0} empty={{ title: "没有容器", description: "Docker 中没有任何容器。" }}>
          {d => (
            <SortableDataTable<CRow>
              rows={d.data.containers.map(x => ({ id: x.id, name: x.name, image: x.image, state: x.state, status: x.status, project: x.project ?? "", protected: x.protected }))}
              columns={containerColumns}
              rowKey="id"
              caption="Docker 容器"
            />
          )}
        </Section>
      )}
      {view === "projects" && (
        <Section title="Compose 项目" description="按 com.docker.compose.project 标签识别" query={inv} isEmpty={d => d.data.projects.length === 0} empty={{ title: "没有 compose 项目", description: "没有带 compose 标签的容器。" }}>
          {d => (
            <ul className={styles.list}>
              {d.data.projects.map(p => (
                <li key={p.name} className={local.providerRow}>
                  <div className={local.providerMain}>
                    <span className={styles.row}>
                      <span className={styles.strong}>{p.name}</span>
                      <Badge size="sm" tone={p.running === p.total ? "success" : p.running === 0 ? "neutral" : "warning"} dot>{p.running}/{p.total} 运行中</Badge>
                    </span>
                    <span className={`${styles.small} ${styles.muted}`}>{p.services.join(", ")}{p.working_dir ? ` · ${p.working_dir}` : ""}</span>
                  </div>
                  {can(c, "docker", "project") && (
                    <span className={local.rowActions}>
                      {(["start", "restart", "stop"] as Action[]).map(a => (
                        <Button key={a} size="sm" variant="ghost" onClick={() => setConfirm({ title: `${ACTION_LABEL[a]}项目 ${p.name}？`, description: `将${ACTION_LABEL[a]}该项目的 ${p.total} 个容器。`, call: "docker.project", args: { name: p.name, action: a }, danger: a === "stop" })}>{ACTION_LABEL[a]}</Button>
                      ))}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Section>
      )}
      {view === "images" && (
        <Section title="镜像" query={images} flush isEmpty={d => d.data.length === 0} empty={{ title: "没有镜像", description: "本机没有任何镜像。" }}>
          {d => <SortableDataTable<IRow> rows={d.data.map(i => ({ id: i.id, tags: i.tags.join(", "), size: i.size, created: i.created, containers: i.containers, dangling: i.dangling }))} columns={imageColumns} rowKey="id" caption="Docker 镜像" />}
        </Section>
      )}
      {view === "volumes" && (
        <Section title="卷" query={volumes} flush isEmpty={d => d.data.length === 0} empty={{ title: "没有卷", description: "本机没有任何数据卷。" }}>
          {d => <SortableDataTable<VRow> rows={d.data.map(v => ({ ...v, actions: v.name }))} columns={volumeColumns} rowKey="name" caption="Docker 卷" />}
        </Section>
      )}
      {view === "networks" && (
        <Section title="网络" query={networks} flush isEmpty={d => d.data.length === 0} empty={{ title: "没有网络", description: "没有读到 Docker 网络。" }}>
          {d => <SortableDataTable<NRow> rows={d.data as NRow[]} columns={networkColumns} rowKey="id" caption="Docker 网络" />}
        </Section>
      )}

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={o => { if (!o) setConfirm(null); }}
        title={confirm?.title ?? ""}
        description={confirm?.description}
        danger={confirm?.danger}
        requireText={confirm?.requireText}
        onConfirm={async () => { if (confirm) await run(confirm); }}
      />
      <PullDialog open={pulling} onOpenChange={setPulling} onPull={reference => run({ title: "", description: "", call: "docker.image_pull", args: { reference } })} />
    </>
  );
}

function PullDialog({ open, onOpenChange, onPull }: { open: boolean; onOpenChange: (o: boolean) => void; onPull: (reference: string) => Promise<void> }) {
  const [ref, setRef] = useState("");
  const [busy, setBusy] = useState(false);
  const valid = /^[A-Za-z0-9][A-Za-z0-9_.\-/:@]{0,254}$/.test(ref.trim());
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    try {
      await onPull(ref.trim());
      setRef("");
      onOpenChange(false);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="拉取镜像" description="只拉取镜像，不会重启任何容器。仅支持公开镜像。">
        <form className={local.form} onSubmit={submit}>
          <Input label="镜像" value={ref} onChange={e => setRef(e.target.value)} description="例如 nginx:1.27 或 ghcr.io/org/app:2.1；省略标签时为 latest" required autoFocus />
          <div className={local.actions}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
            <Button type="submit" disabled={!valid} loading={busy}>拉取</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
