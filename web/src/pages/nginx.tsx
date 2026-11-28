import { useEffect, useMemo, useRef, useState } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { SortableDataTable, type DataColumn } from "@/components/arc/sortable-data-table/sortable-data-table";
import { Switch } from "@/components/arc/switch/switch";
import { api } from "@/api/client";
import { useStreamEvent } from "@/api/live";
import type { Finding, NginxSite, NginxSites, OpsCapabilities, OpsJob, SiteSpec } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { OpsJobLog } from "@/components/job-log";
import { CertDialog } from "@/components/nginx-cert-dialog";
import { NginxFilesDialog } from "@/components/nginx-files-dialog";
import { NginxServicePanel } from "@/components/nginx-service-panel";
import { SiteDrawer, type SiteDrawerTarget } from "@/components/nginx-site-drawer";
import { JobResult, OpsNotice, can, diffOf, useOpsAction, useOpsCaps } from "@/components/ops";
import { PageHeader, Panel, Section, errorMessage, useNow } from "@/components/panel";
import { findingSeverityLabel, findingSeverityTone } from "@/lib/labels";
import { certStatus, covers, formatListen, formatListenCompact, formatSiteDomains, siteKindLabel } from "@/lib/nginx-site";
import { navigate, useRoute } from "@/lib/router";
import siteStyles from "@/components/nginx-site.module.css";
import styles from "./pages.module.css";
import local from "./settings.module.css";

type SiteRow = { [K in keyof NginxSite]: NginxSite[K] } & { names: string };

export default function NginxPage() {
  const route = useRoute();
  const caps = useOpsCaps();
  const sites = useQuery(() => api.opsRead<NginxSites>("nginx.sites"), []);
  const findings = useQuery(() => api.findings(), []);
  const ops = useOpsAction();
  const now = useNow();
  const [refreshKey, setRefreshKey] = useState(0);
  const [toggle, setToggle] = useState<SiteRow | null>(null);
  const [drawerTarget, setDrawerTarget] = useState<SiteDrawerTarget | null>(null);
  const [remove, setRemove] = useState<SiteRow | null>(null);
  const [purge, setPurge] = useState(false);
  const [certFor, setCertFor] = useState<string | null>(null);
  const [findingError, setFindingError] = useState<string | null>(null);
  const [askingFinding, setAskingFinding] = useState<number | null>(null);
  const consumedLinkRef = useRef<string | null>(null);
  const drawerSeqRef = useRef(0);

  // Config files open in a dialog: /nginx?files=<path> (empty = no file selected).
  const legacyFiles = route.segments[1] === "files";
  const filesParam = legacyFiles ? null : route.params.get("files");
  const filesOpen = filesParam !== null;
  const c = caps.data;
  const nginxCaps = c?.domains.nginx;
  const allowSite = can(c, "nginx", "site");
  const allowEdit = can(c, "nginx", "edit");
  const allowManage = can(c, "nginx", "manage");
  const allowCert = can(c, "nginx", "cert");
  const siteList = useMemo(() => sites.data?.data.sites ?? [], [sites.data]);
  const certSite = siteList.find(s => s.file === certFor) ?? null;

  // Keep the open site drawer reflecting fresh site state (cert, enabled, target) after reloads.
  const liveDrawerTarget: SiteDrawerTarget | null = useMemo(
    () => (drawerTarget && drawerTarget.mode !== "create"
      ? {
          ...drawerTarget,
          site: siteList.find(s => s.file === drawerTarget.site.file) ?? drawerTarget.site,
        }
      : drawerTarget),
    [drawerTarget, siteList],
  );

  useStreamEvent("approval", e => {
    if (e.status === "executed") {
      sites.reload();
      setRefreshKey(k => k + 1);
    }
  });

  const siteParam = route.params.get("site");
  const tabParam = route.params.get("tab") === "agent" ? "agent" : "site";
  const linkKey = siteParam ? `${siteParam}:${tabParam}` : null;

  // Old full-page route /nginx/files?path=X now opens the dialog.
  const legacyPath = legacyFiles ? route.params.get("path") ?? "" : null;
  useEffect(() => {
    if (legacyPath !== null) navigate(`/nginx?files=${encodeURIComponent(legacyPath)}`, { replace: true });
  }, [legacyPath]);

  useEffect(() => {
    if (!linkKey) {
      consumedLinkRef.current = null;
      return;
    }
    if (linkKey === consumedLinkRef.current || siteList.length === 0) return;
    const match = siteList.find(s => s.name === siteParam);
    if (match) {
      consumedLinkRef.current = linkKey;
      setDrawerTarget({ id: ++drawerSeqRef.current, mode: tabParam, site: match });
    }
  }, [linkKey, siteList, siteParam, tabParam]);

  const openFiles = (path?: string) => {
    navigate(`/nginx?files=${encodeURIComponent(path ?? "")}`);
  };
  const selectFile = (path: string | null) => {
    navigate(`/nginx?files=${encodeURIComponent(path ?? "")}`, { replace: true });
  };
  const closeFiles = () => navigate("/nginx", { replace: true });
  const reloadAll = () => {
    sites.reload();
    setRefreshKey(k => k + 1);
  };

  // Site settings and the Agent assistant are separate drawers; each can switch to the other.
  const openSite = (site: NginxSite, mode: "site" | "agent" = "site") => {
    ops.setError(null);
    setDrawerTarget({ id: ++drawerSeqRef.current, mode, site });
  };

  const closeDrawer = () => {
    setDrawerTarget(null);
    if (route.params.has("site")) navigate("/nginx", { replace: true });
  };

  const afterChange = (j: OpsJob | null) => {
    if (j?.status === "succeeded" && !j.dry_run) {
      sites.reload();
      setRefreshKey(k => k + 1);
    }
  };

  // After a save: issue the certificate right away (ACME), or ask for the upload.
  const onSaved = async (spec: SiteSpec, j: OpsJob) => {
    setRefreshKey(k => k + 1);
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
    const cert = site?.cert;
    const missing = cert && (cert.not_after === null || spec.domains.some(d => !cert.names.some(n => covers(n, d))));
    if (!missing || !site) return;
    if (spec.ssl.mode === "acme" && site.enabled) {
      afterChange(await ops.run("nginx.cert_issue", { name: spec.name }, false, { follow: true }));
    } else if (spec.ssl.mode === "upload") {
      setCertFor(site.file);
    }
  };

  const askFinding = async (f: Finding) => {
    setAskingFinding(f.id);
    setFindingError(null);
    try {
      const { id } = await api.createConversation({
        title: `nginx 优化：${f.title}`.slice(0, 60),
        context: {
          text: `发现条目：${f.title}\n级别：${findingSeverityLabel[f.severity]}\n详情：${f.detail}\n证据：${f.evidence || "无"}`,
        },
        message: `请帮我分析这条 nginx 建议：「${f.title}」。先调用工具读取相关配置文件核实当前情况，再给出具体优化方案；如果适合通过面板修改，请说明原因并提交变更申请。`,
      });
      navigate(`/agent/${id}`);
    } catch (e) {
      setFindingError(errorMessage(e instanceof Error ? e : new Error(String(e))));
    } finally {
      setAskingFinding(null);
    }
  };

  const nginxFindings = (findings.data ?? []).filter(f => f.category === "nginx" || f.category === "perf" || f.category === "cert");

  const columns: DataColumn<SiteRow>[] = [
    {
      key: "name", label: "站点", sortable: true, render: (_v, r) => (
        <button type="button" className={siteStyles.siteNameButton} onClick={() => openSite(r)} aria-label={`查看或管理站点 ${r.name}`}>
          <span className={siteStyles.siteNameRow}>
            <code className={styles.code}>{r.name}</code>
            {r.managed ? <Badge size="sm" tone="info">{siteKindLabel[r.kind ?? "proxy"]}</Badge> : <Badge size="sm" tone="neutral" outline>手动</Badge>}
            {r.drifted && <Badge size="sm" tone="warning">已手动修改</Badge>}
            {!r.managed && r.ssl && <Badge size="sm" tone="neutral">TLS</Badge>}
          </span>
        </button>
      ),
    },
    {
      key: "names", label: "域名与端口", render: (_v, r) => (
        <div className={siteStyles.domainCell}>
          <span className={siteStyles.domainNames} title={formatSiteDomains(r.server_names)}>{formatSiteDomains(r.server_names)}</span>
          <span className={siteStyles.subMeta} title={formatListen(r.listen)}>{formatListenCompact(r.listen)}</span>
        </div>
      ),
    },
    {
      key: "target", label: "目标", render: (_v, r) => r.target
        ? <code className={`${styles.code} ${styles.small} ${siteStyles.targetCell}`} title={r.target}>{r.target}</code>
        : <span className={`${styles.small} ${styles.muted}`}>—</span>,
    },
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
      // Certificates, config files and delete live in the site drawer header to keep rows on one line.
      key: "file", label: "", render: (_v, r) => (
        <span className={siteStyles.siteActions}>
          <Button size="sm" variant="ghost" onClick={() => openSite(r)}>{r.managed && allowManage ? "编辑" : "管理"}</Button>
          <Button size="sm" variant="ghost" onClick={() => openSite(r, "agent")}>问代理</Button>
        </span>
      ),
    },
  ];

  return (
    <>
      <PageHeader title="nginx" description="按站点管理域名、反向代理、静态站点与 SSL 证书；编辑站点时可由代理撰写配置，「问代理」打开独立的代理助手">
        <Button variant="secondary" onClick={() => openFiles()}>配置文件</Button>
        {allowManage && <Button onClick={() => { ops.setError(null); setDrawerTarget({ id: ++drawerSeqRef.current, mode: "create" }); }}>新建站点</Button>}
      </PageHeader>

      <OpsNotice caps={c} domain="nginx" source={sites.data?.source} />
      <SetupHint caps={c} />
      {ops.error && !drawerTarget && !certSite && !filesOpen && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}
      {ops.job?.status === "running"
        ? <OpsJobLog id={ops.job.id} />
        : ops.job && !(ops.job.dry_run && diffOf(ops.job)) && !drawerTarget && !filesOpen && <Panel title="最近一次操作"><JobResult job={ops.job} onDismiss={() => ops.setJob(null)} /></Panel>}

      <NginxServicePanel caps={c} ops={ops} refreshKey={refreshKey} onChanged={reloadAll} />

      <Section
        title="站点"
        description={sites.data ? (sites.data.data.layout === "sites_enabled" ? "sites-available / sites-enabled 布局 · 点击站点查看与编辑" : "conf.d 布局（停用 = 改名为 .conf.disabled）· 点击站点查看与编辑") : undefined}
        query={sites}
        flush
        isEmpty={d => d.data.sites.length === 0}
        empty={{ title: "还没有站点", description: allowManage ? "点右上角“新建站点”，可手动填写或由代理直接撰写配置。" : "未找到 sites-available 或含 server 块的 conf.d 文件。" }}
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

      <Section
        title="优化、加固与证书提醒"
        description="根据 nginx 配置、站点证书和最近一小时的访问统计生成，每次安全巡检时刷新"
        query={findings}
        isEmpty={() => nginxFindings.length === 0}
        empty={{ title: "暂无建议", description: "配置与访问统计没有发现明显问题（或尚未完成首次巡检）。" }}
      >
        {() => (
          <div className={styles.stack}>
            {findingError && <Alert tone="danger" title="无法开始对话" onDismiss={() => setFindingError(null)}>{findingError}</Alert>}
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
                  <div className={local.rowActions}>
                    <Button size="sm" variant="ghost" loading={askingFinding === f.id} onClick={() => void askFinding(f)}>问代理</Button>
                  </div>
                </li>
              ))}
            </ul>
          </div>
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
        target={liveDrawerTarget}
        onOpenChange={o => { if (!o) closeDrawer(); }}
        caps={nginxCaps}
        allowManage={allowManage}
        allowCert={allowCert}
        allowEdit={allowEdit}
        findings={nginxFindings}
        ops={ops}
        refreshKey={refreshKey}
        onOpenFiles={p => { setDrawerTarget(null); openFiles(p); }}
        onOpenCert={file => setCertFor(file)}
        onOpenSite={openSite}
        onDelete={site => { closeDrawer(); setPurge(false); setRemove({ ...site, names: site.server_names.join(" ") }); }}
        onSaved={onSaved}
        onChanged={reloadAll}
      />
      <NginxFilesDialog
        open={filesOpen}
        onOpenChange={o => { if (!o) closeFiles(); }}
        caps={c}
        sites={siteList}
        path={filesParam || null}
        allowEdit={allowEdit}
        ops={ops}
        refreshKey={refreshKey}
        onSelectPath={selectFile}
        onReloadSites={reloadAll}
      />
      <CertDialog site={certSite} onOpenChange={o => { if (!o) setCertFor(null); }} caps={nginxCaps} ops={ops} onDone={afterChange} />
    </>
  );
}

/** Shown when the helper manages nginx but form sites or certificates are not allowed yet. */
function SetupHint({ caps }: { caps: OpsCapabilities | undefined }) {
  const n = caps?.domains.nginx;
  if (!caps?.write_ready || !n?.enabled) return null;
  const missing = ["manage", "cert", "service", "install", "upgrade"].filter(op => !n.allow.includes(op));
  const acmeOff = n.allow.includes("cert") && n.acme && !n.acme.enabled;
  if (missing.length === 0 && !acmeOff) return null;
  const allow = [...new Set([...n.allow, ...missing])].map(a => `"${a}"`).join(", ");
  const certHint = missing.includes("cert") || acmeOff;
  const runtime = missing.includes("install") ? `\n# 运行方式：auto（默认）、host 或 docker\n# runtime = "auto"` : "";
  const acme = certHint ? `\n\n[nginx.acme]\nenabled = true\n# email = "ops@example.com"` : "";
  const snippet = `[nginx]\nenabled = true\nallow = [${allow}]${runtime}${acme}`;
  const title = missing.includes("manage") ? "开启表单建站与证书管理" : certHint ? "开启自动申请证书" : "开启 nginx 服务、安装与版本管理";
  return (
    <Alert tone="info" title={title}>
      <p className={styles.textSecondary}>
        出于安全考虑，权限只能在服务器上修改。把下面的内容合并到 /etc/tsmonitor/helper.toml，然后执行 systemctl restart tsmonitor-helper。
      </p>
      <CodeBlock code={snippet} language="toml" filename="helper.toml" maxLines={10} />
    </Alert>
  );
}
