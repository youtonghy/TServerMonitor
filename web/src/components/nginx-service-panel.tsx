// nginx service on the nginx page: runtime, version, start/stop, logs, Docker install and version management.
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { Select } from "@/components/arc/select/select";
import { Skeleton } from "@/components/arc/skeleton/skeleton";
import { ApiError, api } from "@/api/client";
import type { NginxLogTail, NginxStatus, NginxVersion, NginxVersions, OpsCapabilities, OpsJob } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { can, type useOpsAction } from "@/components/ops";
import { Facts, QueryView, Section, useNow } from "@/components/panel";
import { formatDuration } from "@/lib/format";
import pageStyles from "@/pages/pages.module.css";
import local from "@/pages/settings.module.css";
import opsStyles from "./ops.module.css";
import styles from "./nginx-site.module.css";

const RUNTIME_LABEL: Record<NginxStatus["runtime"], string> = { host: "系统包", docker: "Docker 容器", none: "未安装" };
const CHANNEL_LABEL: Record<NginxVersion["channel"], string> = { stable: "稳定版", mainline: "主线版" };
const CHANNELS = [{ value: "stable", label: "稳定版" }, { value: "mainline", label: "主线版" }];
const LOG_FILES = [{ value: "error", label: "错误日志" }, { value: "access", label: "访问日志" }];
const LOG_LINES = 200;
const VERSION_RE = /^\d+\.\d+\.\d+$/;

/** A confirmation waiting in the shared ConfirmDialog. */
type Pending =
  | { kind: "stop" }
  | { kind: "restart" }
  | { kind: "upgrade"; version?: string }
  | { kind: "rollback"; image: string };

interface Props {
  caps: OpsCapabilities | undefined;
  ops: ReturnType<typeof useOpsAction>;
  /** Increment to re-read the status (e.g. after an approval executed). */
  refreshKey: number;
  /** Called after a change that may affect sites (install, upgrade, rollback). */
  onChanged: () => void;
}

/** The helper is not running or does not manage nginx: the page's OpsNotice already says so. */
function unsupported(e: Error | null): boolean {
  return e instanceof ApiError && e.status === 503;
}

export function NginxServicePanel({ caps, ops, refreshKey, onChanged }: Props) {
  const status = useQuery(() => api.opsRead<NginxStatus>("nginx.status"), [refreshKey]);
  const now = useNow();
  const [pending, setPending] = useState<Pending | null>(null);
  const [logsOpen, setLogsOpen] = useState(false);
  const [installOpen, setInstallOpen] = useState(false);
  const [versionsOpen, setVersionsOpen] = useState(false);

  if (status.status === "error" && status.data === undefined && unsupported(status.error)) return null;

  const s = status.data?.data;
  const allow = (op: string) => can(caps, "nginx", op);
  const busy = ops.busy !== null;

  const done = (j: OpsJob | null, sitesToo = false) => {
    if (j && !j.dry_run) {
      // reload on failure too: an upgrade that reverted still changed what is running
      status.reload();
      if (sitesToo && j.status === "succeeded") onChanged();
    }
  };
  const service = async (action: "start" | "stop" | "restart") => done(await ops.run("nginx.service", { action }, false, { follow: true }));
  const install = async (version: string) => {
    setInstallOpen(false);
    done(await ops.run("nginx.install", { version }, false, { follow: true }), true);
  };
  const confirmPending = async () => {
    if (!pending) return;
    if (pending.kind === "stop" || pending.kind === "restart") await service(pending.kind);
    else if (pending.kind === "upgrade") done(await ops.run("nginx.upgrade", pending.version ? { version: pending.version } : {}, false, { follow: true }), true);
    else done(await ops.run("nginx.rollback", {}, false, { follow: true }), true);
  };

  const installed = Boolean(s && s.runtime !== "none");
  const hostUpgrade = s?.runtime === "host" && s.package?.candidate && s.package.candidate !== s.package.installed ? s.package.candidate : null;

  const actions = s && (
    <span className={styles.serviceActions}>
      {installed && allow("service") && (s.running
        ? (
          <>
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => setPending({ kind: "restart" })}>重启</Button>
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => setPending({ kind: "stop" })}>停止</Button>
          </>
        )
        : <Button size="sm" loading={ops.busy === "nginx.service"} disabled={busy} onClick={() => void service("start")}>启动</Button>)}
      {installed && allow("test") && <Button size="sm" variant="secondary" loading={ops.busy === "nginx.test"} onClick={() => ops.run("nginx.test")}>检查配置</Button>}
      {installed && s.running && allow("reload") && <Button size="sm" variant="secondary" loading={ops.busy === "nginx.reload"} onClick={() => ops.run("nginx.reload")}>重新加载</Button>}
      {installed && <Button size="sm" variant="ghost" onClick={() => setLogsOpen(true)}>查看日志</Button>}
      {s.runtime === "docker" && allow("upgrade") && <Button size="sm" variant="ghost" onClick={() => setVersionsOpen(true)}>版本管理</Button>}
      {hostUpgrade && allow("upgrade") && <Button size="sm" variant="ghost" disabled={busy} onClick={() => setPending({ kind: "upgrade" })}>升级到 {hostUpgrade}</Button>}
      {!installed && allow("install") && <Button size="sm" onClick={() => setInstallOpen(true)}>用 Docker 安装 nginx</Button>}
    </span>
  );

  const confirm = pendingCopy(pending, s);

  return (
    <>
      <Section
        title="nginx 服务"
        description="运行方式、版本与服务控制；操作经运维助手执行"
        actions={actions}
        query={status}
        skeletonLines={3}
      >
        {d => <StatusBody s={d.data} now={now} canInstall={allow("install")} />}
      </Section>

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={o => { if (!o) setPending(null); }}
        title={confirm.title}
        description={confirm.description}
        danger={confirm.danger}
        confirmLabel={confirm.label}
        onConfirm={confirmPending}
      >
        {confirm.warning && <Alert tone="warning" title="无法自动回退">{confirm.warning}</Alert>}
      </ConfirmDialog>
      <LogDialog open={logsOpen} onOpenChange={setLogsOpen} />
      {s && (
        <InstallDialog
          open={installOpen}
          onOpenChange={setInstallOpen}
          blockers={s.install_blockers}
          busy={busy}
          onInstall={v => void install(v)}
        />
      )}
      {s?.runtime === "docker" && (
        <VersionsDialog
          open={versionsOpen}
          onOpenChange={setVersionsOpen}
          status={s}
          busy={busy}
          onPick={version => { setVersionsOpen(false); setPending({ kind: "upgrade", version }); }}
          onRollback={image => { setVersionsOpen(false); setPending({ kind: "rollback", image }); }}
        />
      )}
    </>
  );
}

function pendingCopy(p: Pending | null, s: NginxStatus | undefined): { title: string; description: string; label: string; danger?: boolean; warning?: string } {
  switch (p?.kind) {
    case "stop":
      return { title: "停止 nginx？", description: "停止后所有站点都将无法访问，直到再次启动。", label: "停止", danger: true };
    case "restart":
      return { title: "重启 nginx？", description: "重启会短暂中断正在进行的连接；只想应用配置时请用“重新加载”。", label: "重启" };
    case "upgrade":
      if (p.version) {
        return {
          title: `切换到 nginx ${p.version}？`,
          description: `运维助手会拉取 ${p.version} 镜像，用新镜像对当前配置执行 nginx -t，通过后替换容器并探测；任一步失败会自动恢复为当前版本。`,
          label: "切换版本",
        };
      }
      return {
        title: `升级 nginx 到 ${s?.package?.candidate ?? ""}？`,
        description: "通过 apt 升级 nginx 软件包，完成后检查配置并确认 nginx 正常运行。",
        label: "升级",
        warning: "系统包升级无法自动回退。如果新版本出现问题，需要在服务器上手动降级。",
      };
    case "rollback":
      return { title: `回退到 ${p.image}？`, description: "用上一个镜像替换当前容器，先执行 nginx -t，失败时保持当前版本。", label: "回退" };
    default:
      return { title: "", description: "", label: "确认执行" };
  }
}

function StatusBody({ s, now, canInstall }: { s: NginxStatus; now: number; canInstall: boolean }) {
  if (s.runtime === "none") {
    return (
      <p className={pageStyles.textSecondary}>
        没有检测到 nginx（系统包与 Docker 容器都没有）。
        {canInstall ? "可以用 Docker 安装官方镜像，配置目录沿用 /etc/nginx。" : ""}
      </p>
    );
  }
  const uptime = s.running && s.started_at ? formatDuration(now / 1000 - s.started_at) : "—";
  const items = [
    { label: "运行方式", value: <>{RUNTIME_LABEL[s.runtime]}{s.configured_runtime !== "auto" && <span className={pageStyles.muted}>（helper.toml 指定）</span>}</> },
    { label: "版本", value: s.version ? <code className={pageStyles.code}>{s.version}</code> : "—" },
    { label: "状态", value: <Badge size="sm" tone={s.running ? "success" : "danger"} dot>{s.running ? "运行中" : "已停止"}</Badge> },
    { label: "工作进程", value: s.workers ?? "—" },
    { label: "已运行", value: uptime },
  ];
  if (s.runtime === "host") items.push({ label: "systemd 服务", value: s.service ? <code className={pageStyles.code}>{s.service}</code> : "—" });
  if (s.container) {
    items.push({ label: "容器", value: <code className={pageStyles.code}>{s.container.name}</code> });
    items.push({ label: "镜像", value: <code className={pageStyles.code}>{s.container.image}</code> });
  }
  if (s.package) {
    const newer = s.package.candidate && s.package.candidate !== s.package.installed;
    items.push({ label: "已安装软件包", value: s.package.installed ? <code className={pageStyles.code}>{s.package.installed}</code> : "—" });
    items.push({ label: "apt 可用版本", value: newer ? <Badge size="sm" tone="info">{s.package.candidate}</Badge> : <span className={pageStyles.muted}>已是最新</span> });
  }
  return (
    <>
      <Facts items={items} />
      {(s.build || s.modules.length > 0) && (
        <details className={styles.disclosure}>
          <summary>编译模块（{s.modules.length}）</summary>
          {s.build && <p className={opsStyles.muted}>{s.build}</p>}
          {s.modules.length > 0 && (
            <ul className={styles.moduleList}>
              {s.modules.map(m => <li key={m}><Badge size="sm" tone="neutral" outline>{m}</Badge></li>)}
            </ul>
          )}
        </details>
      )}
    </>
  );
}

function LogDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="nginx 日志" description={`最近 ${LOG_LINES} 行，只读`} className={styles.logDialog}>
        <LogBody />
      </DialogContent>
    </Dialog>
  );
}

function LogBody() {
  const [file, setFile] = useState("error");
  const log = useQuery(() => api.opsRead<NginxLogTail>("nginx.log_tail", { file, lines: String(LOG_LINES) }), [file]);
  return (
    <div className={styles.filesBody}>
      <div className={pageStyles.between}>
        <SegmentedControl label="日志文件" options={LOG_FILES} value={file} onValueChange={setFile} />
        <Button size="sm" variant="secondary" loading={log.refreshing && log.status !== "loading"} onClick={log.reload}>刷新</Button>
      </div>
      <QueryView query={log} skeletonLines={10} errorTitle="无法读取日志">
        {d => (
          <>
            <p className={opsStyles.muted}>
              <code className={pageStyles.code}>{d.data.path}</code>
              {d.data.truncated ? `，仅显示最后 ${d.data.lines.length} 行` : ""}
            </p>
            {d.data.lines.length === 0
              ? <p className={pageStyles.textSecondary}>日志为空。</p>
              : <pre className={styles.logView}>{d.data.lines.join("\n")}</pre>}
          </>
        )}
      </QueryView>
    </div>
  );
}

interface InstallDialogProps {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  blockers: string[];
  busy: boolean;
  onInstall: (version: string) => void;
}

function InstallDialog({ open, onOpenChange, ...props }: InstallDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="用 Docker 安装 nginx"
        description="拉取官方 nginx 镜像并以容器运行，沿用 /etc/nginx 中的配置；安装后即可在这里管理站点。"
        className={opsStyles.wide}
      >
        <InstallBody {...props} onCancel={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  );
}

function InstallBody({ blockers, busy, onInstall, onCancel }: Omit<InstallDialogProps, "open" | "onOpenChange"> & { onCancel: () => void }) {
  const versions = useQuery(() => api.opsRead<NginxVersions>("nginx.versions"), []);
  const [channel, setChannel] = useState<string>("stable");
  const [picked, setPicked] = useState<string | null>(null);
  const [manual, setManual] = useState("");

  const list = versions.data?.data.versions ?? [];
  const inChannel = list.filter(v => v.channel === channel);
  const fallback = versions.status === "error" && list.length === 0;
  const chosen = fallback
    ? manual.trim()
    : (picked && inChannel.some(v => v.version === picked) ? picked : (inChannel.find(v => v.latest) ?? inChannel[0])?.version ?? "");
  const valid = VERSION_RE.test(chosen);
  const blocked = blockers.length > 0;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (valid && !blocked) onInstall(chosen);
  };

  return (
    <form className={opsStyles.confirmBody} onSubmit={submit}>
      {blocked && (
        <Alert tone="warning" title="暂时无法安装">
          <ul className={pageStyles.list}>{blockers.map(b => <li key={b}>{b}</li>)}</ul>
        </Alert>
      )}
      {versions.status === "loading" && <Skeleton lines={2} label="正在读取可用版本" />}
      {fallback && (
        <>
          <Alert tone="warning" title="无法读取版本列表">请手动填写要安装的版本号。</Alert>
          <Input label="版本" value={manual} onChange={e => setManual(e.target.value)} placeholder="例如 1.27.3" description="官方镜像 nginx:<版本>" autoComplete="off" />
        </>
      )}
      {list.length > 0 && (
        <>
          <SegmentedControl label="发布渠道" options={CHANNELS} value={channel} onValueChange={c => { setChannel(c); setPicked(null); }} />
          <Select
            label="版本"
            value={chosen}
            onValueChange={setPicked}
            options={inChannel.map(v => ({ value: v.version, label: v.latest ? `${v.version}（最新）` : v.version }))}
            description={versions.data ? `镜像 ${versions.data.data.image}:${chosen || "<版本>"}` : undefined}
          />
        </>
      )}
      <div className={opsStyles.confirmActions}>
        <Button type="button" variant="ghost" onClick={onCancel}>取消</Button>
        <Button type="submit" disabled={!valid || blocked || busy}>安装</Button>
      </div>
    </form>
  );
}

interface VersionsDialogProps {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  status: NginxStatus;
  busy: boolean;
  onPick: (version: string) => void;
  onRollback: (image: string) => void;
}

function VersionsDialog({ open, onOpenChange, ...props }: VersionsDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="版本管理"
        description="切换前用新镜像对当前配置执行 nginx -t，替换容器后探测；任一步失败会自动恢复为当前版本。"
        className={opsStyles.wide}
      >
        <VersionsBody {...props} />
      </DialogContent>
    </Dialog>
  );
}

function VersionsBody({ status, busy, onPick, onRollback }: Omit<VersionsDialogProps, "open" | "onOpenChange">) {
  const versions = useQuery(() => api.opsRead<NginxVersions>("nginx.versions"), []);
  return (
    <div className={opsStyles.confirmBody}>
      <p className={opsStyles.muted}>
        当前：<code className={pageStyles.code}>{status.container?.image ?? status.version ?? "—"}</code>
      </p>
      {status.previous_image && (
        <div className={pageStyles.between}>
          <span className={pageStyles.textSecondary}>上次切换前的镜像仍保留，可以直接回退。</span>
          <Button size="sm" variant="secondary" disabled={busy} onClick={() => onRollback(status.previous_image as string)}>回退到 {status.previous_image}</Button>
        </div>
      )}
      <QueryView query={versions} skeletonLines={5} errorTitle="无法读取版本列表">
        {d => (
          <ul className={`${pageStyles.list} ${styles.versionList}`}>
            {d.data.versions.map(v => {
              const current = v.version === status.version;
              return (
                <li key={v.version} className={local.providerRow}>
                  <div className={local.providerMain}>
                    <span className={pageStyles.row}>
                      <code className={pageStyles.code}>{v.version}</code>
                      <Badge size="sm" tone={v.channel === "stable" ? "neutral" : "info"} outline>{CHANNEL_LABEL[v.channel]}</Badge>
                      {v.latest && <Badge size="sm" tone="info">最新</Badge>}
                      {current && <Badge size="sm" tone="success" dot>当前</Badge>}
                    </span>
                  </div>
                  <div className={local.rowActions}>
                    <Button size="sm" variant="ghost" disabled={current || busy} onClick={() => onPick(v.version)}>{current ? "使用中" : "切换"}</Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </QueryView>
    </div>
  );
}
