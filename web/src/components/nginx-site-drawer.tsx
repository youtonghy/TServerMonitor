// Create / edit a managed nginx site: a form instead of a config file. The helper renders the
// config from it; "预览" shows the resulting diff before anything is written.
import { useState, type FormEvent, type ReactNode } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { Drawer, DrawerContent } from "@/components/arc/drawer/drawer";
import { Input } from "@/components/arc/input/input";
import SegmentedControl from "@/components/arc/segmented-control/segmented-control";
import { Select } from "@/components/arc/select/select";
import { Switch } from "@/components/arc/switch/switch";
import { Textarea } from "@/components/arc/textarea/textarea";
import type { NginxSiteDetail, OpsDomainCaps, OpsJob, SiteSpec, SslMode } from "@/api/types";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { diffOf, type useOpsAction } from "@/components/ops";
import { SITE_NAME, defaultSpec, nameFromDomain, parseDomains, siteKindLabel, sslModeLabel } from "@/lib/nginx-site";
import opsStyles from "./ops.module.css";
import styles from "./nginx-site.module.css";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** null = new site */
  detail: NginxSiteDetail | null;
  caps: OpsDomainCaps | undefined;
  allowCert: boolean;
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  onSaved: (spec: SiteSpec, job: OpsJob) => void;
}

export function SiteDrawer(props: Props) {
  return (
    <Drawer open={props.open} onOpenChange={props.onOpenChange}>
      <DrawerContent
        title={props.detail ? `编辑站点 ${props.detail.spec.name}` : "新建站点"}
        description="填写表单即可，配置文件由运维助手按内置模板生成；保存前可预览改动"
        className={styles.drawer}
      >
        {props.open && <SiteForm key={props.detail?.sha256 ?? "new"} {...props} />}
      </DrawerContent>
    </Drawer>
  );
}

function Field({ children, wide }: { children: ReactNode; wide?: boolean }) {
  return <div className={wide ? styles.wide : undefined}>{children}</div>;
}

function SiteForm({ onOpenChange, detail, caps, allowCert, allowEdit, ops, onSaved }: Props) {
  const editing = detail !== null;
  const [spec, setSpec] = useState<SiteSpec>(() => (detail ? structuredClone(detail.spec) : defaultSpec()));
  const [domainsText, setDomainsText] = useState(() => (detail ? detail.spec.domains.join("\n") : ""));
  const [nameTouched, setNameTouched] = useState(editing);
  const [rootTouched, setRootTouched] = useState(editing);
  const [overwrite, setOverwrite] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
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
