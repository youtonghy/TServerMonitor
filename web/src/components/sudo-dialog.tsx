import { useEffect, useRef, useState, type FormEvent } from "react";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { api, ApiError, setSudoHandler } from "@/api/client";
import styles from "./form-dialog.module.css";

/**
 * Asks for the account password when the server answers `sudo_required` (server changes,
 * account and token management). A confirmation is valid for ten minutes.
 */
export function SudoDialog() {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef<((ok: boolean) => void) | null>(null);

  useEffect(() => {
    setSudoHandler(() => new Promise<boolean>(resolve => {
      // a second request while the dialog is open waits for the same answer
      const prev = pending.current;
      pending.current = ok => {
        prev?.(ok);
        resolve(ok);
      };
      setPassword("");
      setError(null);
      setOpen(true);
    }));
    return () => setSudoHandler(null);
  }, []);

  const finish = (ok: boolean) => {
    pending.current?.(ok);
    pending.current = null;
    setOpen(false);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.sudo(password);
      finish(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "确认失败");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={o => { if (!o) finish(false); }}>
      <DialogContent title="确认密码" description="修改服务器、管理账号或令牌前需要再次输入密码，确认后 10 分钟内不再询问。">
        <form className={styles.form} onSubmit={submit}>
          <Input
            label="当前密码"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            error={error ?? undefined}
            autoFocus
            required
          />
          <div className={styles.actions}>
            <Button type="button" variant="ghost" onClick={() => finish(false)}>取消</Button>
            <Button type="submit" loading={busy}>确认</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
