import { useState, type ReactNode } from "react";
import { Activity, Bell, Bot, BrickWall, CalendarClock, ClipboardList, Globe, MonitorPlay, PackageCheck, Boxes, FileText, KeyRound, LayoutDashboard, LockKeyhole, ScrollText, Settings, ShieldCheck, Terminal, TrendingUp, type LucideIcon } from "lucide-react";
import { Badge } from "@/components/arc/badge/badge";
import { Button } from "@/components/arc/button/button";
import { ThemeSwitch } from "@/components/arc/theme-switch/theme-switch";
import { Tooltip } from "@/components/arc/tooltip/tooltip";
import { MOCK } from "@/api/client";
import { useConnection, type ConnectionState } from "@/api/live";
import { Link, useRoute } from "@/lib/router";
import { useTheme } from "@/lib/theme";
import { OpsTokenDialog } from "./ops-token-dialog";
import { PendingBanner } from "./pending-banner";
import { TokenDialog } from "./token-dialog";
import styles from "./app-shell.module.css";

interface NavItem { to: string; label: string; icon: LucideIcon; match: string }

export const NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: "监控",
    items: [
      { to: "/", label: "总览", icon: LayoutDashboard, match: "" },
      { to: "/trends", label: "趋势", icon: TrendingUp, match: "trends" },
      { to: "/logs", label: "日志", icon: ScrollText, match: "logs" },
      { to: "/security", label: "安全", icon: ShieldCheck, match: "security" },
      { to: "/alerts", label: "告警", icon: Bell, match: "alerts" },
      { to: "/wall", label: "大屏", icon: MonitorPlay, match: "wall" },
    ],
  },
  {
    label: "运维",
    items: [
      { to: "/containers", label: "Docker", icon: Boxes, match: "containers" },
      { to: "/nginx", label: "nginx", icon: Globe, match: "nginx" },
      { to: "/firewall", label: "防火墙", icon: BrickWall, match: "firewall" },
      { to: "/ssh", label: "SSH", icon: Terminal, match: "ssh" },
      { to: "/packages", label: "软件更新", icon: PackageCheck, match: "packages" },
      { to: "/ops", label: "运维记录", icon: ClipboardList, match: "ops" },
    ],
  },
  {
    label: "智能",
    items: [
      { to: "/reports", label: "报告", icon: FileText, match: "reports" },
      { to: "/agent", label: "Agent", icon: Bot, match: "agent" },
      { to: "/tasks", label: "自动任务", icon: CalendarClock, match: "tasks" },
    ],
  },
  { label: "系统", items: [{ to: "/settings", label: "设置", icon: Settings, match: "settings" }] },
];

export const NAV: NavItem[] = NAV_GROUPS.flatMap(g => g.items);

const connectionLabel: Record<ConnectionState, string> = { connecting: "正在连接", open: "实时数据已连接", closed: "实时数据已断开" };

export function AppShell({ children }: { children: ReactNode }) {
  const route = useRoute();
  const [theme, setTheme] = useTheme();
  const connection = useConnection();
  const [tokenOpen, setTokenOpen] = useState(false);
  const [opsTokenOpen, setOpsTokenOpen] = useState(false);
  const active = route.segments[0] ?? "";

  return (
    <div className={styles.shell}>
      <aside className={styles.sidebar}>
        <Link to="/" className={styles.brand} aria-label="TServerMonitor 总览">
          <Activity size={20} strokeWidth={1.75} aria-hidden="true" />
          <span>TServerMonitor</span>
        </Link>
        <nav aria-label="主导航" className={styles.nav}>
          {NAV_GROUPS.map(group => (
            <div key={group.label} className={styles.navGroup}>
              <p className={styles.navGroupLabel} id={`nav-${group.label}`}>{group.label}</p>
              <ul className={styles.navList} aria-labelledby={`nav-${group.label}`}>
                {group.items.map(item => {
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
            </div>
          ))}
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
            <Tooltip content="运维令牌">
              <Button variant="ghost" size="sm" aria-label="设置运维令牌" onClick={() => setOpsTokenOpen(true)}>
                <LockKeyhole size={16} strokeWidth={1.75} aria-hidden="true" />
              </Button>
            </Tooltip>
          </div>
        </div>
      </aside>
      <main className={styles.main}>
        <div className={styles.page}>
          <PendingBanner />
          {children}
        </div>
      </main>
      <TokenDialog open={tokenOpen} onOpenChange={setTokenOpen} />
      <OpsTokenDialog open={opsTokenOpen} onOpenChange={setOpsTokenOpen} />
    </div>
  );
}
