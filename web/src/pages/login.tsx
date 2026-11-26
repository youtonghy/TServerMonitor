import { useState, type FormEvent } from "react";
import { Activity } from "lucide-react";
import { Alert } from "@/components/arc/alert/alert";
import { Button } from "@/components/arc/button/button";
import { Input } from "@/components/arc/input/input";
import { api, ApiError } from "@/api/client";
import styles from "./auth.module.css";

export default function LoginPage({ onDone, expired }: { onDone: () => void; expired?: boolean }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.login(username, password);
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "登录失败");
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className={styles.screen}>
      <form className={styles.card} onSubmit={submit}>
        <span className={styles.brand}><Activity size={20} strokeWidth={1.75} aria-hidden="true" />TServerMonitor</span>
        <h1 className={styles.title}>登录</h1>
        {expired && !error && <Alert tone="info" title="需要重新登录">登录已过期或在其他地方退出。</Alert>}
        {error && <Alert tone="danger" title="登录失败">{error}</Alert>}
        <div className={styles.form}>
          <Input label="用户名" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" autoFocus required />
          <Input label="密码" type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required />
        </div>
        <div className={styles.actions}>
          <span className={styles.lead}>忘记密码请在服务器上执行 tsmonitor reset-password</span>
          <Button type="submit" loading={busy}>登录</Button>
        </div>
      </form>
    </main>
  );
}
