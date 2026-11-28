// nginx site drawer: create/edit managed sites, edit manual sites, or (in its own mode) chat with the Agent.
import { useState, type FormEvent, type ReactNode } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { Drawer, DrawerContent, useDrawerItem } from "@/components/arc/drawer/drawer";
import { Input } from "@/components/arc/input/input";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { Select } from "@/components/arc/select/select";
import { Switch } from "@/components/arc/switch/switch";
import { Textarea } from "@/components/arc/textarea/textarea";
import { api } from "@/api/client";
import type { Finding, NginxSite, NginxSiteDetail, OpsDomainCaps, OpsJob, SiteSpec, SslMode } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { NginxDraftBox, SiteAgentPanel, type DraftSuggestion } from "@/components/nginx-agent";
import { NginxFileEditor } from "@/components/nginx-file-editor";
import { diffOf, type useOpsAction } from "@/components/ops";
import { QueryView } from "@/components/panel";
import { findingSeverityLabel, findingSeverityTone } from "@/lib/labels";
import { SITE_NAME, defaultSpec, formatListen, formatSiteDomains, nameFromDomain, parseDomains, siteKindLabel, sslModeLabel } from "@/lib/nginx-site";
import pageStyles from "@/pages/pages.module.css";
import opsStyles from "./ops.module.css";
import styles from "./nginx-site.module.css";

export type SiteDrawerTarget =
  | { id: number; mode: "create" }
  | { id: number; mode: "site"; site: NginxSite }
  | { id: number; mode: "agent"; site: NginxSite };

interface Props {
  target: SiteDrawerTarget | null;
  onOpenChange: (open: boolean) => void;
  caps: OpsDomainCaps | undefined;
  allowManage: boolean;
  allowCert: boolean;
  allowEdit: boolean;
  findings: Finding[];
  ops: ReturnType<typeof useOpsAction>;
  refreshKey: number;
  onOpenFiles: (path: string) => void;
  onOpenCert: (file: string) => void;
  onOpenSite: (site: NginxSite, mode: "site" | "agent") => void;
  onDelete: (site: NginxSite) => void;
  onSaved: (spec: SiteSpec, job: OpsJob) => void;
  onChanged: () => void;
}

export function SiteDrawer(props: Props) {
  const shown = useDrawerItem(props.target);

  const title = !shown
    ? "站点"
    : shown.mode === "create"
      ? "新建站点"
      : shown.mode === "agent"
        ? `代理助手 · ${shown.site.name}`
        : `${shown.site.managed ? "站点" : "手动站点"} ${shown.site.name}`;
  const description = !shown
    ? undefined
    : shown.mode === "create"
      ? "可让代理直接撰写配置或手动填写表单；保存前可预览改动"
      : `${formatSiteDomains(shown.site.server_names)} · ${shown.site.file}`;

  return (
    <Drawer open={props.target !== null} onOpenChange={props.onOpenChange}>
      <DrawerContent title={title} description={description} className={styles.drawer}>
        {shown && (
          <SiteDrawerBody
            key={shown.id}
            target={shown}
            caps={props.caps}
            allowManage={props.allowManage}
            allowCert={props.allowCert}
            allowEdit={props.allowEdit}
            findings={props.findings}
            ops={props.ops}
            refreshKey={props.refreshKey}
            onOpenChange={props.onOpenChange}
            onOpenFiles={props.onOpenFiles}
            onOpenCert={props.onOpenCert}
            onOpenSite={props.onOpenSite}
            onDelete={props.onDelete}
            onSaved={props.onSaved}
            onChanged={props.onChanged}
          />
        )}
      </DrawerContent>
    </Drawer>
  );
}

function SiteDrawerBody({
  target,
  caps,
  allowManage,
  allowCert,
  allowEdit,
  findings,
  ops,
  refreshKey,
  onOpenChange,
  onOpenFiles,
  onOpenCert,
  onOpenSite,
  onDelete,
  onSaved,
  onChanged,
}: Omit<Props, "target"> & { target: SiteDrawerTarget }) {
  if (target.mode === "create") {
    return (
      <SiteForm
        detail={null}
        caps={caps}
        allowCert={allowCert}
        allowEdit={allowEdit}
        ops={ops}
        onOpenChange={onOpenChange}
        onSaved={onSaved}
      />
    );
  }

  const site = target.site;

  if (target.mode === "agent") {
    return (
      <SiteAgentPanel
        site={site}
        onApplied={onChanged}
        actions={<Button type="button" size="sm" variant="ghost" onClick={() => onOpenSite(site, "site")}>站点设置</Button>}
      />
    );
  }

  const siteFindings = matchingFindings(findings, site);
  const openAgent = () => onOpenSite(site, "agent");

  return (
    <div>
      <div className={styles.drawerTopBar}>
        <Button type="button" size="sm" variant="secondary" onClick={openAgent}>问代理</Button>
        <div className={styles.drawerTopActions}>
          {site.managed && site.cert && site.cert.mode !== "none" && (
            <Button type="button" size="sm" variant="ghost" onClick={() => onOpenCert(site.file)}>证书</Button>
          )}
          <Button type="button" size="sm" variant="ghost" onClick={() => onOpenFiles(site.file)}>配置文件</Button>
          {site.managed && allowManage && (
            <Button type="button" size="sm" variant="ghost" onClick={() => onDelete(site)}>删除站点</Button>
          )}
        </div>
      </div>

      {site.managed ? (
        <ManagedSiteConfig
          site={site}
          findings={siteFindings}
          caps={caps}
          allowManage={allowManage}
          allowCert={allowCert}
          allowEdit={allowEdit}
          ops={ops}
          refreshKey={refreshKey}
          onOpenChange={onOpenChange}
          onSaved={onSaved}
          onAskAgent={openAgent}
        />
      ) : (
        <ManualSiteConfig
          site={site}
          findings={siteFindings}
          allowEdit={allowEdit}
          ops={ops}
          refreshKey={refreshKey}
          onChanged={onChanged}
          onAskAgent={openAgent}
        />
      )}
    </div>
  );
}

function matchingFindings(findings: Finding[], site: NginxSite): Finding[] {
  const tokens = [site.name, site.file, ...site.server_names.filter(n => n !== "_")].map(x => x.toLowerCase());
  return findings.filter(f => {
    const hay = `${f.title} ${f.detail} ${f.evidence}`.toLowerCase();
    return tokens.some(t => t.length >= 2 && hay.includes(t));
  });
}

function SiteFindings({ items, onAsk }: { items: Finding[]; onAsk: () => void }) {
  if (items.length === 0) return null;
  return (
    <Alert tone="warning" title={`发现 ${items.length} 条与本站点相关的建议`}>
      <div className={pageStyles.stack}>
        <ul className={pageStyles.list}>
          {items.map(f => (
            <li key={f.id}>
              <span className={pageStyles.row}>
                <Badge size="sm" tone={findingSeverityTone[f.severity]}>{findingSeverityLabel[f.severity]}</Badge>
                <span className={pageStyles.strong}>{f.title}</span>
              </span>
              <span className={pageStyles.textSecondary}>{f.detail}</span>
            </li>
          ))}
        </ul>
        <div>
          <Button type="button" size="sm" variant="secondary" onClick={onAsk}>让代理分析并优化</Button>
        </div>
      </div>
    </Alert>
  );
}

function ManagedSiteConfig({
  site,
  findings,
  caps,
  allowManage,
  allowCert,
  allowEdit,
  ops,
  refreshKey,
  onOpenChange,
  onSaved,
  onAskAgent,
}: {
  site: NginxSite;
  findings: Finding[];
  caps: OpsDomainCaps | undefined;
  allowManage: boolean;
  allowCert: boolean;
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  refreshKey: number;
  onOpenChange: (open: boolean) => void;
  onSaved: (spec: SiteSpec, job: OpsJob) => void;
  onAskAgent: () => void;
}) {
  const detail = useQuery(
    () => (allowManage ? api.opsRead<NginxSiteDetail>("nginx.site_get", { name: site.name }) : Promise.resolve(null)),
    [site.name, allowManage, refreshKey],
  );

  if (!allowManage) {
    return (
      <div className={styles.stackBody}>
        <SiteFacts site={site} />
        <SiteFindings items={findings} onAsk={onAskAgent} />
        <Alert tone="info" title="只读模式">
          此主机未开启表单建站权限（helper.toml 的 [nginx] allow 需要包含 manage）。你仍可以点「问代理」向代理提问，或查看完整配置文件。
        </Alert>
      </div>
    );
  }

  return (
    <QueryView query={detail} skeletonLines={8} errorTitle="无法读取站点设置">
      {d => d ? (
        <div className={styles.stackBody}>
          <SiteForm
            notice={<SiteFindings items={findings} onAsk={onAskAgent} />}
            key={d.data.sha256 ?? site.file}
            detail={d.data}
            caps={caps}
            allowCert={allowCert}
            allowEdit={allowEdit}
            ops={ops}
            onOpenChange={onOpenChange}
            onSaved={onSaved}
          />
        </div>
      ) : null}
    </QueryView>
  );
}

function ManualSiteConfig({
  site,
  findings,
  allowEdit,
  ops,
  refreshKey,
  onChanged,
  onAskAgent,
}: {
  site: NginxSite;
  findings: Finding[];
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  refreshKey: number;
  onChanged: () => void;
  onAskAgent: () => void;
}) {
  return (
    <div className={styles.stackBody}>
      <NginxFileEditor
        embedded
        path={site.file}
        allowEdit={allowEdit}
        ops={ops}
        refreshKey={refreshKey}
        onSaved={onChanged}
      />
      <SiteFindings items={findings} onAsk={onAskAgent} />
      <SiteFacts site={site} />
    </div>
  );
}

function SiteFacts({ site }: { site: NginxSite }) {
  return (
    <dl className={styles.facts}>
      <dt>域名</dt><dd>{formatSiteDomains(site.server_names)}</dd>
      <dt>监听端口</dt><dd>{formatListen(site.listen)}</dd>
      <dt>目标</dt><dd>{site.target ? <code className={styles.monoCode}>{site.target}</code> : "—"}</dd>
      <dt>TLS</dt><dd>{site.ssl ? "已配置" : "未配置"}</dd>
      <dt>状态</dt><dd><Badge size="sm" tone={site.enabled ? "success" : "neutral"} dot>{site.enabled ? "已启用" : "已停用"}</Badge></dd>
    </dl>
  );
}

function Field({ children, wide }: { children: ReactNode; wide?: boolean }) {
  return <div className={wide ? styles.wide : undefined}>{children}</div>;
}

const CREATE_SUGGESTIONS: DraftSuggestion[] = [
  { label: "反代本机服务", prompt: "为 app.example.com 配置反向代理到 http://127.0.0.1:3000，支持 WebSocket 与自动申请 HTTPS" },
  { label: "前端 SPA 静态站", prompt: "创建一个单页应用静态站点（SPA 回退到 index.html），开启 30 天静态缓存与自动 HTTPS" },
  { label: "含安全加固的反代", prompt: "配置反向代理站点，限制上传 20 MiB 并屏蔽 /.env、/.git 敏感路径扫描" },
];

const EDIT_SUGGESTIONS: DraftSuggestion[] = [
  { label: "防扫描与安全头", prompt: "保留现有域名和目标地址，在自定义配置中屏蔽 /.env、/.git、/.svn 扫描并添加基础安全响应头" },
  { label: "调大上传与超时", prompt: "保留现有配置，将上传大小限制调整为 50 MiB，代理超时调整为 180 秒" },
  { label: "开启自动 HTTPS", prompt: "保留现有域名和目标地址，将 SSL 方式切换为自动申请并开启强制 HTTPS" },
];

interface SiteFormProps {
  detail: NginxSiteDetail | null;
  caps: OpsDomainCaps | undefined;
  allowCert: boolean;
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  onOpenChange: (open: boolean) => void;
  onSaved: (spec: SiteSpec, job: OpsJob) => void;
  /** Rendered right below the Agent drafting box, e.g. findings for this site. */
  notice?: ReactNode;
}

function SiteForm({ onOpenChange, detail, caps, allowCert, allowEdit, ops, onSaved, notice }: SiteFormProps) {
  const editing = detail !== null;
  const [spec, setSpec] = useState<SiteSpec>(() => (detail ? structuredClone(detail.spec) : defaultSpec()));
  const [domainsText, setDomainsText] = useState(() => (detail ? detail.spec.domains.join("\n") : ""));
  const [nameTouched, setNameTouched] = useState(editing);
  const [rootTouched, setRootTouched] = useState(editing);
  const [overwrite, setOverwrite] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [undoSpec, setUndoSpec] = useState<{ spec: SiteSpec; domainsText: string } | null>(null);
  const [advanced, setAdvanced] = useState(Boolean(detail && (detail.spec.extra || detail.spec.listen.http !== 80 || detail.spec.listen.https !== 443)));

  const roots = caps?.site_roots ?? ["/var/www"];
  const acme = caps?.acme;
  const domains = parseDomains(domainsText);
  const suggestedRoot = (name: string) => (name ? `${roots[0].replace(/\/$/, "")}/${name}` : "");

  // Filling in the domains fills in the name and the document root until they are edited by hand.
  const onDomains = (text: string) => {
    setDomainsText(text);
    const first = parseDomains(text)[0] ?? "";
    if (!nameTouched) {
      const name = nameFromDomain(first);
      setSpec(s => ({ ...s, name, static: rootTouched ? s.static : { ...s.static, root: suggestedRoot(name) } }));
    }
  };
  const set = <K extends keyof SiteSpec>(k: K, v: SiteSpec[K]) => setSpec(s => ({ ...s, [k]: v }));
  const feat = (k: keyof SiteSpec["features"], v: boolean | number) => setSpec(s => ({ ...s, features: { ...s.features, [k]: v } }));

  const applyDraft = (next: SiteSpec) => {
    setUndoSpec({ spec: structuredClone(spec), domainsText });
    const merged = editing ? { ...next, name: spec.name } : next;
    setSpec(merged);
    setDomainsText(merged.domains.join("\n"));
    setNameTouched(true);
    setRootTouched(true);
    if (merged.extra || merged.listen.http !== 80 || merged.listen.https !== 443) {
      setAdvanced(true);
    }
  };

  const undoDraft = () => {
    if (!undoSpec) return;
    setSpec(undoSpec.spec);
    setDomainsText(undoSpec.domainsText);
    setUndoSpec(null);
  };

  const wildcard = domains.some(d => d.startsWith("*."));
  const sslOptions = (Object.keys(sslModeLabel) as SslMode[]).map(m => ({
    value: m,
    label: sslModeLabel[m] + (m === "acme" && !acme?.enabled ? "（未开启）" : ""),
    disabled: m !== "none" && (!allowCert || (m === "acme" && (!acme?.enabled || wildcard))),
  }));

  const nameOk = SITE_NAME.test(spec.name) && !/\.(conf|disabled)$/.test(spec.name);
  const targetOk = spec.kind === "proxy" ? /^https?:\/\/\S+$/.test(spec.proxy.upstream.trim()) : spec.static.root.startsWith("/");
  const valid = nameOk && domains.length > 0 && targetOk;
  const tls = spec.ssl.mode !== "none";

  const payload = () => ({
    spec: { ...spec, domains, proxy: { ...spec.proxy, upstream: spec.proxy.upstream.trim() } },
    base_sha256: detail?.sha256 ?? null,
    overwrite,
  });
  const review = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    const j = await ops.run("nginx.site_save", payload(), true);
    if (j?.status === "succeeded") setPreview(diffOf(j) ?? "");
  };
  const save = async () => {
    const p = payload();
    const j = await ops.run("nginx.site_save", p, false);
    if (j?.status === "succeeded") {
      onSaved(p.spec, j);
      onOpenChange(false);
    }
  };

  return (
    <form className={styles.form} onSubmit={review}>
      <NginxDraftBox
        mode="site"
        siteName={editing || (nameTouched && spec.name) ? spec.name : undefined}
        spec={{ ...spec, domains }}
        suggestions={editing ? EDIT_SUGGESTIONS : CREATE_SUGGESTIONS}
        title={editing ? "让代理撰写或修改站点配置" : "用一句话让代理撰写站点配置"}
        description="代理会自动核对本机端口、容器与现有域名，直接填写下方表单；核对后点击「预览并保存」。"
        onApplySite={applyDraft}
        canUndo={undoSpec !== null}
        onUndo={undoDraft}
      />

      {notice}
      {detail?.drifted && (
        <Alert tone="warning" title="配置文件被手动修改过">
          保存会用表单内容重新生成 {detail.file}，手动修改将丢失（预览中可以看到）。
          <Switch label="确认覆盖手动修改" checked={overwrite} onCheckedChange={setOverwrite} />
        </Alert>
      )}
      {ops.error && <Alert tone="danger" title="无法保存" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}

      <section className={styles.group}>
        <h3 className={styles.groupTitle}>基本信息</h3>
        <SegmentedControl
          label="站点类型"
          options={[{ value: "proxy", label: siteKindLabel.proxy }, { value: "static", label: siteKindLabel.static }]}
          value={spec.kind}
          onValueChange={(v: string) => set("kind", v === "static" ? "static" : "proxy")}
        />
        <Textarea
          label="域名"
          description="每行一个，可绑定多个；也可以用空格或逗号分隔"
          value={domainsText}
          onChange={e => onDomains(e.target.value)}
          rows={3}
          placeholder={"example.com\nwww.example.com"}
          required
        />
        <Input
          label="站点名"
          description={editing ? "创建后不能修改" : "用作配置文件名、证书目录和日志文件名，默认取自第一个域名"}
          value={spec.name}
          onChange={e => { setNameTouched(true); set("name", e.target.value); if (!rootTouched) setSpec(s => ({ ...s, static: { ...s.static, root: suggestedRoot(e.target.value) } })); }}
          error={spec.name && !nameOk ? "只能包含字母、数字、. _ -，最长 64 个字符" : undefined}
          disabled={editing}
          required
        />
      </section>

      <section className={styles.group}>
        <h3 className={styles.groupTitle}>{spec.kind === "proxy" ? "反向代理" : "静态文件"}</h3>
        {spec.kind === "proxy" ? (
          <>
            <Input label="目标地址" description="请求转发到这里，例如本机应用端口" placeholder="http://127.0.0.1:3000" value={spec.proxy.upstream} onChange={e => set("proxy", { ...spec.proxy, upstream: e.target.value })} required />
            <div className={styles.switches}>
              <Switch label="WebSocket 支持" checked={spec.proxy.websocket} onCheckedChange={v => set("proxy", { ...spec.proxy, websocket: v })} />
              <Switch label="传递原始 Host 头" checked={spec.proxy.pass_host} onCheckedChange={v => set("proxy", { ...spec.proxy, pass_host: v })} />
            </div>
          </>
        ) : (
          <>
            <Input label="网站根目录" description={`必须位于 ${roots.join("、")} 之下；不存在时自动创建`} value={spec.static.root} onChange={e => { setRootTouched(true); set("static", { ...spec.static, root: e.target.value }); }} required />
            <Input label="首页文件" value={spec.static.index} onChange={e => set("static", { ...spec.static, index: e.target.value })} />
            <div className={styles.switches}>
              <Switch label="单页应用（未知路径回退到 index.html）" checked={spec.static.spa} onCheckedChange={v => set("static", { ...spec.static, spa: v })} />
            </div>
          </>
        )}
      </section>

      <section className={styles.group}>
        <h3 className={styles.groupTitle}>SSL 证书</h3>
        <Select label="证书方式" value={spec.ssl.mode} onValueChange={v => set("ssl", { ...spec.ssl, mode: v as SslMode })} options={sslOptions} />
        {!allowCert && <p className={opsStyles.muted}>此主机未允许证书操作（helper.toml 的 [nginx] allow 需要包含 cert）。</p>}
        {spec.ssl.mode === "acme" && (
          <p className={opsStyles.muted}>
            保存后自动向 {acme?.custom_directory ? "自定义 CA" : acme?.staging ? "Let's Encrypt 测试环境（证书不受浏览器信任）" : "Let's Encrypt"} 申请证书，并在到期前 {acme?.renew_days ?? 30} 天内自动续期。要求域名已解析到本机、80 端口可从公网访问。
          </p>
        )}
        {spec.ssl.mode === "upload" && <p className={opsStyles.muted}>保存后在站点列表点“证书”上传证书和私钥；上传前站点只提供 HTTP。</p>}
        {spec.ssl.mode === "path" && (
          <div className={styles.grid}>
            <Input label="证书文件（fullchain）" placeholder="/etc/letsencrypt/live/example.com/fullchain.pem" value={spec.ssl.cert_path} onChange={e => set("ssl", { ...spec.ssl, cert_path: e.target.value })} required />
            <Input label="私钥文件" placeholder="/etc/letsencrypt/live/example.com/privkey.pem" value={spec.ssl.key_path} onChange={e => set("ssl", { ...spec.ssl, key_path: e.target.value })} required />
            <p className={`${opsStyles.muted} ${styles.wide}`}>只能引用 {(caps?.cert_paths ?? []).join("、") || "允许的目录"} 下的文件。</p>
          </div>
        )}
      </section>

      <section className={styles.group}>
        <h3 className={styles.groupTitle}>功能</h3>
        <div className={styles.switches}>
          <Switch label="强制 HTTPS（HTTP 跳转到 HTTPS）" checked={spec.features.force_https} disabled={!tls} onCheckedChange={v => feat("force_https", v)} />
          <Switch label="HTTP/2" checked={spec.features.http2} disabled={!tls} onCheckedChange={v => feat("http2", v)} />
          <Switch label="HSTS（浏览器只用 HTTPS 访问）" checked={spec.features.hsts} disabled={!tls} onCheckedChange={v => feat("hsts", v)} />
          <Switch label="gzip 压缩" checked={spec.features.gzip} onCheckedChange={v => feat("gzip", v)} />
          {spec.kind === "static" && <Switch label="静态资源缓存（30 天）" checked={spec.features.static_cache} onCheckedChange={v => feat("static_cache", v)} />}
          <Switch label="独立访问日志与错误日志" checked={spec.features.access_log} onCheckedChange={v => feat("access_log", v)} />
        </div>
        <Input
          label="上传大小限制（MiB）"
          description="0 表示使用 nginx 默认值 1 MiB"
          type="number"
          min={0}
          max={10240}
          value={String(spec.features.client_max_body_mb)}
          onChange={e => feat("client_max_body_mb", Math.max(0, Number(e.target.value) || 0))}
        />
      </section>

      <section className={styles.group}>
        <Switch label="高级设置" checked={advanced} onCheckedChange={setAdvanced} />
        {advanced && (
          <>
            <div className={styles.grid}>
              <Input label="HTTP 端口" type="number" min={1} max={65535} value={String(spec.listen.http)} onChange={e => set("listen", { ...spec.listen, http: Number(e.target.value) || 0 })} />
              <Input label="HTTPS 端口" type="number" min={1} max={65535} value={String(spec.listen.https)} onChange={e => set("listen", { ...spec.listen, https: Number(e.target.value) || 0 })} />
              {spec.kind === "proxy" && <Input label="代理超时（秒）" type="number" min={1} max={3600} value={String(spec.proxy.timeout_secs)} onChange={e => set("proxy", { ...spec.proxy, timeout_secs: Number(e.target.value) || 0 })} />}
            </div>
            <Switch label="同时监听 IPv6" checked={spec.listen.ipv6} onCheckedChange={v => set("listen", { ...spec.listen, ipv6: v })} />
            {spec.ssl.mode === "acme" && spec.listen.http !== 80 && <p className={opsStyles.muted}>自动申请证书需要监听 80 端口。</p>}
            <Field wide>
              <div className={styles.monoField}>
                <Textarea
                  label="自定义配置"
                  description={allowEdit ? "追加到 server 块末尾的指令，例如额外的 location；需要 edit 权限" : "需要在 helper.toml 的 [nginx] allow 中开启 edit 才能使用"}
                  value={spec.extra}
                  onChange={e => set("extra", e.target.value)}
                  rows={5}
                  disabled={!allowEdit}
                  spellCheck={false}
                  placeholder={"location /api/ {\n    proxy_pass http://127.0.0.1:4000;\n}"}
                />
              </div>
            </Field>
          </>
        )}
      </section>

      <div className={styles.footer}>
        <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
        <Button type="submit" disabled={!valid || (detail?.drifted === true && !overwrite)} loading={ops.busy === "nginx.site_save"}>预览并保存</Button>
      </div>

      <ConfirmDialog
        open={preview !== null}
        onOpenChange={o => { if (!o) setPreview(null); }}
        title={editing ? `保存站点 ${spec.name}？` : `创建站点 ${spec.name}？`}
        description="写入后会执行 nginx -t 并重新加载；检查、重载或探测失败时自动恢复原状。"
        confirmLabel={editing ? "保存并重新加载" : "创建并启用"}
        wide
        onConfirm={save}
      >
        {preview ? <CodeBlock code={preview} language="diff" filename={`${spec.name}.diff`} maxLines={28} /> : <p className={opsStyles.muted}>配置内容没有变化。</p>}
      </ConfirmDialog>
    </form>
  );
}
