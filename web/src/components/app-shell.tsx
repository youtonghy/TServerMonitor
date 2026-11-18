import { useState, type ReactNode } from "react";
import { Activity, Bot, Boxes, FileText, KeyRound, LayoutDashboard, ScrollText, Settings, ShieldCheck, TrendingUp, type LucideIcon } from "lucide-react";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { ThemeSwitch } from "@/components/arc/theme-switch/theme-switch";
import { Tooltip } from "@/components/arc/tooltip/tooltip";
import { MOCK } from "@/api/client";
import { useConnection, type ConnectionState } from "@/api/live";
import { Link, useRoute } from "@/lib/router";
import { useTheme } from "@/lib/theme";
import { TokenDialog } from "./token-dialog";
import styles from "./app-shell.module.css";

interface NavItem { to: string; label: string; icon: LucideIcon; match: string }

export const NAV: NavItem[] = [
  { to: "/", label: "总览", icon: LayoutDashboard, match: "" },
  { to: "/trends", label: "趋势", icon: TrendingUp, match: "trends" },
  { to: "/containers", label: "容器", icon: Boxes, match: "containers" },
  { to: "/logs", label: "日志", icon: ScrollText, match: "logs" },
  { to: "/security", label: "安全", icon: ShieldCheck, match: "security" },
  { to: "/reports", label: "报告", icon: FileText, match: "reports" },
  { to: "/agent", label: "Agent", icon: Bot, match: "agent" },
  { to: "/settings", label: "设置", icon: Settings, match: "settings" },
];

const connectionLabel: Record<ConnectionState, string> = { connecting: "正在连接", open: "实时数据已连接", closed: "实时数据已断开" };

export function AppShell({ children }: { children: ReactNode }) {
  const route = useRoute();
  const [theme, setTheme] = useTheme();
  const connection = useConnection();
  const [tokenOpen, setTokenOpen] = useState(false);
  const active = route.segments[0] ?? "";

  return (
    <div className={styles.shell}>
      <aside className={styles.sidebar}>
        <Link to="/" className={styles.brand} aria-label="TServerMonitor 总览">
          <Activity size={20} strokeWidth={1.75} aria-hidden="true" />
          <span>TServerMonitor</span>
        </Link>
        <nav aria-label="主导航" className={styles.nav}>
          <ul className={styles.navList}>
            {NAV.map(item => {
              const current = item.match === active;
              const Icon = item.icon;
              return (
                <li key={item.to}>
                  <Link to={item.to} className={styles.navLink} aria-current={current ? "page" : undefined}>
                    <Icon size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>{item.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
        <div className={styles.footer}>
          <p className={styles.connection} data-state={connection} role="status">
            <span className={styles.dot} aria-hidden="true" />
            <span>{connectionLabel[connection]}</span>
          </p>
          {MOCK && <Badge tone="info" size="sm">模拟数据</Badge>}
          <div className={styles.footerTools}>
            <ThemeSwitch theme={theme} iconOnly label={theme === "dark" ? "切换到浅色主题" : "切换到深色主题"} onThemeChange={next => setTheme(next)} />
            <Tooltip content="访问令牌">
              <Button variant="ghost" size="sm" aria-label="设置访问令牌" onClick={() => setTokenOpen(true)}>
                <KeyRound size={16} strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Tooltip>
          </div>
        </div>
      </aside>
      <main className={styles.main}>
        <div className={styles.page}>{children}</div>
      </main>
      <TokenDialog open={tokenOpen} onOpenChange={setTokenOpen} />
    </div>
  );
}
