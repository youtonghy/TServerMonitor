import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Button } from "@/components/arc/button/button";
import { Dialog, DialogContent } from "@/components/arc/dialog/dialog";
import { Input } from "@/components/arc/input/input";
import styles from "./ops.module.css";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  /** Extra content such as a diff or the commands that will run. */
  children?: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  /** When set, the user must type this exact text to enable the button (destructive actions). */
  requireText?: string;
  wide?: boolean;
  onConfirm: () => Promise<unknown> | void;
}

/** Replaces window.confirm for server changes: shows what will happen, optionally type-to-confirm. */
export function ConfirmDialog({ open, onOpenChange, title, description, children, confirmLabel = "确认执行", danger, requireText, wide, onConfirm }: ConfirmDialogProps) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) setTyped("");
  }, [open]);
  const ready = !requireText || typed.trim() === requireText;
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!ready) return;
    setBusy(true);
    try {
      await onConfirm();
      onOpenChange(false);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={title} description={description} className={wide ? styles.wide : undefined}>
        <form className={styles.confirmBody} onSubmit={submit}>
          {children}
          {requireText && (
            <Input
              label={`输入 ${requireText} 以确认`}
              value={typed}
              onChange={e => setTyped(e.target.value)}
              autoComplete="off"
              autoFocus
            />
          )}
          <div className={styles.confirmActions}>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>取消</Button>
            <Button type="submit" variant={danger ? "danger" : "primary"} disabled={!ready} loading={busy}>{confirmLabel}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
