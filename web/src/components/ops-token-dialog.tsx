import { useEffect, useState, type FormEvent } from "react";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import { getOpsToken, onOpsTokenNeeded, setOpsToken } from "@/api/client";
import styles from "./token-dialog.module.css";

/** Opens when a management request is refused for the ops token, or from the shell button. */
export function OpsTokenDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [value, setValue] = useState("");
  const [rejected, setRejected] = useState(false);

  useEffect(() => onOpsTokenNeeded(() => {
    setRejected(getOpsToken() !== null);
    onOpenChange(true);
  }), [onOpenChange]);

  useEffect(() => {
    if (open) setValue("");
  }, [open]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setOpsToken(value.trim() || null);
    setRejected(false);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="输入运维令牌"
        description="修改 nginx、防火墙、SSH 和 Docker 需要单独的运维令牌（TSM_OPS_TOKEN）。它只保存在当前页面的内存中，刷新后需要重新输入。"
      >
        <form className={styles.form} onSubmit={submit}>
          <Input
            label="运维令牌"
            type="password"
            autoComplete="off"
            value={value}
            onChange={event => setValue(event.target.value)}
            error={rejected ? "运维令牌无效，请检查后重新输入" : undefined}
            autoFocus
          />
          <div className={styles.actions}>
            {getOpsToken() && (
              <Button type="button" variant="ghost" onClick={() => { setOpsToken(null); onOpenChange(false); }}>
                清除令牌
              </Button>
            )}
            <Button type="submit">使用令牌</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
