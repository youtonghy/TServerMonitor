// Certificate of one managed site: its state, and issuing (ACME) or uploading a new one.
import { useState, type FormEvent } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Textarea } from "@/components/arc/textarea/textarea";
import type { NginxSite, OpsDomainCaps, OpsJob } from "@/api/types";
import { type useOpsAction } from "@/components/ops";
import { useNow } from "@/components/panel";
import { formatDateTime } from "@/lib/format";
import { certStatus, sslModeLabel } from "@/lib/nginx-site";
import opsStyles from "./ops.module.css";
import styles from "./nginx-site.module.css";

interface Props {
  site: NginxSite | null;
  onOpenChange: (open: boolean) => void;
  caps: OpsDomainCaps | undefined;
  ops: ReturnType<typeof useOpsAction>;
  onDone: (job: OpsJob | null) => void;
}

export function CertDialog({ site, onOpenChange, caps, ops, onDone }: Props) {
  return (
    <Dialog open={site !== null} onOpenChange={onOpenChange}>
      <DialogContent title={`站点 ${site?.name ?? ""} 的证书`} description={site?.server_names.join(" ")} className={opsStyles.wide}>
        {site && <CertBody key={site.file} site={site} onOpenChange={onOpenChange} caps={caps} ops={ops} onDone={onDone} />}
      </DialogContent>
    </Dialog>
  );
}

function CertBody({ site, onOpenChange, caps, ops, onDone }: Props & { site: NginxSite }) {
  const now = useNow();
  const c = site.cert;
  const st = certStatus(c, now);
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const mode = c?.mode ?? "none";
  const acme = caps?.acme;

  const issue = async () => {
    const j = await ops.run("nginx.cert_issue", { name: site.name, force: true }, false, { follow: true });
    onDone(j);
    if (j?.status === "succeeded") onOpenChange(false);
  };
  const upload = async (e: FormEvent) => {
    e.preventDefault();
    const j = await ops.run("nginx.cert_upload", { name: site.name, cert_pem: cert, key_pem: key });
    onDone(j);
    if (j?.status === "succeeded") {
      setKey("");
      onOpenChange(false);
    }
  };

  return (
    <div className={styles.form}>
      <dl className={styles.facts}>
        <dt>方式</dt><dd>{sslModeLabel[mode]}</dd>
        <dt>状态</dt><dd><Badge size="sm" tone={st.tone} dot>{st.label}</Badge></dd>
        {c?.names && c.names.length > 0 && <><dt>覆盖域名</dt><dd>{c.names.join(", ")}</dd></>}
        {c?.issuer && <><dt>签发者</dt><dd>{c.issuer}</dd></>}
        {c?.not_after && <><dt>有效期</dt><dd>{formatDateTime(c.not_before)} — {formatDateTime(c.not_after)}</dd></>}
        {c?.last_attempt && <><dt>最近一次申请</dt><dd>{formatDateTime(c.last_attempt)}</dd></>}
      </dl>
      {c?.last_error && <Alert tone="danger" title="最近一次申请失败">{c.last_error}</Alert>}
      {ops.error && <Alert tone="danger" title="操作失败" onDismiss={() => ops.setError(null)}>{ops.error}</Alert>}

      {mode === "acme" && (
        <>
          <p className={opsStyles.muted}>
            助手会先在本机自检验证路径，再向 {acme?.custom_directory ? "自定义 CA" : acme?.staging ? "Let's Encrypt 测试环境" : "Let's Encrypt"} 申请，成功后自动启用 HTTPS。整个过程通常需要几十秒；之后每天检查两次，到期前 {acme?.renew_days ?? 30} 天内自动续期。
          </p>
          <div className={styles.footer}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>关闭</Button>
            <Button type="button" loading={ops.busy === "nginx.cert_issue"} disabled={!site.enabled} onClick={issue}>{c?.not_after ? "立即续期" : "申请证书"}</Button>
          </div>
          {!site.enabled && <p className={opsStyles.muted}>站点已停用，CA 无法访问验证文件；请先启用站点。</p>}
        </>
      )}

      {mode === "upload" && (
        <form className={styles.form} onSubmit={upload}>
          <Textarea label="证书（PEM，含中间证书）" value={cert} onChange={e => setCert(e.target.value)} rows={6} spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" required />
          <Textarea label="私钥（PEM）" description="只发送给运维助手保存（权限 0600），不会写入任务记录，也不会再显示" value={key} onChange={e => setKey(e.target.value)} rows={6} spellCheck={false} autoComplete="off" placeholder="-----BEGIN PRIVATE KEY-----" required />
          <div className={styles.footer}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>关闭</Button>
            <Button type="submit" loading={ops.busy === "nginx.cert_upload"} disabled={!cert.trim() || !key.trim()}>上传并启用 HTTPS</Button>
          </div>
        </form>
      )}

      {(mode === "path" || mode === "none") && (
        <>
          <p className={opsStyles.muted}>{mode === "path" ? "证书由服务器上的其他工具（例如 certbot）维护，续期后在这里点“重新加载”即可生效。" : "此站点未启用 SSL。在“编辑”中选择证书方式。"}</p>
          <div className={styles.footer}><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>关闭</Button></div>
        </>
      )}
    </div>
  );
}
