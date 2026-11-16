import { useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { getToken, onUnauthorized, setToken } from "@/api/client";
import styles from "./token-dialog.module.css";

/** Opens when any request returns 401, or when `open` is set from the shell's token button. */
export function TokenDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [value, setValue] = useState("");
  const [rejected, setRejected] = useState(false);

  useEffect(() => onUnauthorized(() => {
    setRejected(getToken() !== null);
    onOpenChange(true);
  }), [onOpenChange]);

  useEffect(() => {
    if (open) setValue(getToken() ?? "");
  }, [open]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const token = value.trim();
    setToken(token || null);
    setRejected(false);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="输入访问令牌" description="守护进程设置了 TSM_API_TOKEN。令牌只保存在本浏览器中。">
        <form className={styles.form} onSubmit={submit}>
          <Input
            label="访问令牌"
            type="password"
            autoComplete="off"
            value={value}
            onChange={event => setValue(event.target.value)}
            error={rejected ? "当前令牌无效，请检查后重新输入" : undefined}
            autoFocus
          />
          <div className={styles.actions}>
            {getToken() && (
              <Button type="button" variant="ghost" onClick={() => { setToken(null); setValue(""); onOpenChange(false); }}>
                清除令牌
              </Button>
            )}
            <Button type="submit">保存令牌</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
