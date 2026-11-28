// Reusable nginx file editor (with AI drafting, diff preview, and safe reload).
import { lazy, Suspense, useState, type ReactNode } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Button } from "@/components/arc/button/button";
import { CodeBlock } from "@/components/arc/code-block/code-block";
import { Skeleton } from "@/components/arc/skeleton/skeleton";
import { api } from "@/api/client";
import type { NginxFile } from "@/api/types";
import { useQuery } from "@/api/useQuery";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { NginxDraftBox, type DraftSuggestion } from "@/components/nginx-agent";
import { diffOf, type useOpsAction } from "@/components/ops";
import { Panel, errorMessage } from "@/components/panel";
import opsStyles from "@/components/ops.module.css";
import local from "@/pages/settings.module.css";
import siteStyles from "./nginx-site.module.css";

const CodeEditor = lazy(() => import("@/components/code-editor"));

const FILE_SUGGESTIONS: DraftSuggestion[] = [
  { label: "安全头与防扫描", prompt: "在保留现有功能的前提下，补充 X-Content-Type-Options 与 X-Frame-Options 安全响应头，并拦截 /.env、/.git、/.svn 敏感路径请求" },
  { label: "gzip 与缓存优化", prompt: "优化静态资源缓存策略并启用合理的 gzip 压缩配置" },
  { label: "添加 /api/ 反代", prompt: "在现有 server 块内增加 location /api/ 反向代理到 http://127.0.0.1:3000，并透传 Host 和客户端真实 IP" },
];

/** A file being edited: `base` is the sha256 it was read with (null = new file). */
interface Editing { path: string; base: string | null; original: string; draft: string; editable: boolean }

export interface NginxFileEditorProps {
  path: string;
  isNew?: boolean;
  /** Generated from the site form: hand edits are overwritten by the next form save. */
  managed?: boolean;
  allowEdit: boolean;
  ops: ReturnType<typeof useOpsAction>;
  onSaved: () => void;
  /** Render without outer Panel (for use inside a Drawer). */
  embedded?: boolean;
  /** Increment to refresh file content after an external approval. */
  refreshKey?: number;
}

export function NginxFileEditor({ path, isNew, managed, allowEdit, ops, onSaved, embedded, refreshKey = 0 }: NginxFileEditorProps) {
  const file = useQuery(() => (isNew ? Promise.resolve(null) : api.opsRead<NginxFile>("nginx.file", { path })), [path, isNew, refreshKey]);
  const [edit, setEdit] = useState<Editing | null>(() => (
    isNew
      ? { path, base: null, original: "", draft: "server {\n    listen 80;\n    server_name example.com;\n}\n", editable: true }
      : null
  ));
  const [loadedSyncKey, setLoadedSyncKey] = useState<string | null>(null);
  const [undoDraft, setUndoDraft] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const loadError = !isNew && file.status === "error" ? errorMessage(file.error) : null;

  const loaded = !isNew ? file.data?.data : undefined;
  const loadedKey = loaded ? `${path}:${loaded.sha256}` : null;
  if (loaded && loadedKey !== loadedSyncKey) {
    setLoadedSyncKey(loadedKey);
    if (!edit || edit.path !== path || edit.base !== loaded.sha256) {
      setEdit({ path, base: loaded.sha256, original: loaded.content, draft: loaded.content, editable: loaded.editable });
    }
  }

  const wrap = (title: string, description: string | undefined, actions: ReactNode, body: ReactNode) => {
    if (embedded) {
      return (
        <div className={siteStyles.stackBody}>
          <div className={siteStyles.editorHeader}>
            <div className={siteStyles.editorMeta}>
              <span className={siteStyles.groupTitle}><code className={siteStyles.monoCode}>{title}</code></span>
              {description && <span className={opsStyles.muted}>{description}</span>}
            </div>
            {actions && <div className={local.rowActions}>{actions}</div>}
          </div>
          {body}
        </div>
      );
    }
    return <Panel title={title} description={description} actions={actions}>{body}</Panel>;
  };

  if (loadError) return wrap(path, undefined, null, <Alert tone="danger" title="无法读取">{loadError}</Alert>);
  if (!edit) return wrap(path, "正在读取", null, <Skeleton lines={10} label="正在读取" />);

  const canWrite = allowEdit && edit.editable;
  const dirty = edit.draft !== edit.original || Boolean(isNew);
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
      setUndoDraft(null);
      onSaved();
    }
  };

  const description = canWrite ? (isNew ? "新文件" : dirty ? "有未保存的修改" : "与服务器上的文件一致") : "只读";
  const actions = canWrite && (
    <span className={local.rowActions}>
      {!isNew && (
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={!dirty}
          onClick={() => { setEdit({ ...edit, draft: edit.original }); setUndoDraft(null); }}
        >
          放弃修改
        </Button>
      )}
      <Button type="button" size="sm" disabled={!dirty} loading={ops.busy === "nginx.write"} onClick={review}>
        预览并保存
      </Button>
    </span>
  );

  return wrap(
    path,
    description,
    actions,
    <>
      {managed && canWrite && (
        <Alert tone="warning" title="这是面板生成的站点">
          建议在站点列表中点“编辑”修改；在这里手动修改后，下次用表单保存时需要确认覆盖。
        </Alert>
      )}
      {canWrite && (
        <NginxDraftBox
          mode="file"
          path={path}
          content={edit.draft}
          suggestions={FILE_SUGGESTIONS}
          title="让代理撰写或优化此文件"
          description="描述需求后由代理读取上下文并生成完整配置写入下方编辑器；核对后点击「预览并保存」。"
          onApplyFile={next => {
            setUndoDraft(edit.draft);
            setEdit(e => e && { ...e, draft: next });
          }}
          canUndo={undoDraft !== null}
          onUndo={() => {
            if (undoDraft === null) return;
            setEdit(e => e && { ...e, draft: undoDraft });
            setUndoDraft(null);
          }}
        />
      )}
      <Suspense fallback={<Skeleton lines={10} label="正在加载编辑器" />}>
        <CodeEditor
          key={`${path}:${canWrite}`}
          value={edit.draft}
          onChange={draft => setEdit(e => e && { ...e, draft })}
          readOnly={!canWrite}
          label={`编辑 ${path}`}
        />
      </Suspense>
      {!canWrite && !edit.editable && (
        <p className={opsStyles.muted}>这个文件不在可编辑目录中（helper.toml 的 nginx.edit_dirs）。</p>
      )}
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
    </>,
  );
}
