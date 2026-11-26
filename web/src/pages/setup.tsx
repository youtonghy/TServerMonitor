import { useState, type FormEvent } from "react";
import { Activity } from "lucide-react";
import { Alert } from "@/components/arc/alert/alert";
import { Button } from "@/components/arc/button/button";
import { Input } from "@/components/arc/input/input";
import { api, ApiError } from "@/api/client";
import styles from "./auth.module.css";

/** First start: create the administrator account. Needs the one-time setup code from the server. */
export default function SetupPage({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState(0);
  const [code, setCode] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const mismatch = repeat.length > 0 && repeat !== password;
  const short = password.length > 0 && password.length < 10;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (step === 0) {
      setStep(1);
      return;
    }
    if (mismatch || short) return;
    setBusy(true);
    setError(null);
    try {
      await api.setup(code, username, password);
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "初始化失败");
      // a wrong code sends the user back to the first step
      if (err instanceof ApiError && err.message.includes("setup 码")) setStep(0);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className={styles.screen}>
      <form className={styles.card} onSubmit={submit}>
        <span className={styles.brand}><Activity size={20} strokeWidth={1.75} aria-hidden="true" />TServerMonitor</span>
        <div className={styles.steps} aria-hidden="true">
          <span className={styles.step} data-done="true" />
          <span className={styles.step} data-done={step >= 1} />
        </div>
        {step === 0 ? (
          <>
            <h1 className={styles.title}>初始化</h1>
            <p className={styles.lead}>
              还没有管理员账号。为了确认你能访问这台服务器，请输入启动时生成的 setup 码。它保存在服务器上的数据目录中，也会打印在启动日志里：
            </p>
            <p className={styles.code}>cat /var/lib/tsmonitor/setup-code<br />journalctl -u tsmonitor | grep "setup code"</p>
            {error && <Alert tone="danger" title="无法继续">{error}</Alert>}
            <div className={styles.form}>
              <Input label="setup 码" value={code} onChange={e => setCode(e.target.value)} autoComplete="off" autoFocus required maxLength={64} />
            </div>
            <div className={styles.actions}>
              <span />
              <Button type="submit" disabled={!code.trim()}>下一步</Button>
            </div>
          </>
        ) : (
          <>
            <h1 className={styles.title}>创建管理员</h1>
            <p className={styles.lead}>之后访问面板、API 与 MCP 都需要登录；MCP 客户端和脚本请在「设置」中创建 API 令牌。</p>
            {error && <Alert tone="danger" title="创建失败">{error}</Alert>}
            <div className={styles.form}>
              <Input label="用户名" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" required minLength={3} maxLength={32} pattern="[A-Za-z0-9_.\-]+" description="3–32 位字母、数字、下划线、点或连字符" />
              <Input label="密码" type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" required error={short ? "至少 10 位" : undefined} autoFocus />
              <Input label="再次输入密码" type="password" value={repeat} onChange={e => setRepeat(e.target.value)} autoComplete="new-password" required error={mismatch ? "两次输入不一致" : undefined} />
            </div>
            <div className={styles.actions}>
              <Button type="button" variant="ghost" onClick={() => setStep(0)}>上一步</Button>
              <Button type="submit" loading={busy} disabled={!password || mismatch || short}>创建并登录</Button>
            </div>
          </>
        )}
      </form>
    </main>
  );
}
