// Chinese labels and tones for enum values from the API.
import type { BadgeTone } from "@/components/arc/badge/badge";
import type {
  AgentRunStatus, AgentStep, Confidence, FindingSeverity, Mode, Priority,
  RecommendationCategory, ReportKind, Severity,
} from "@/api/types";

export const modeLabel: Record<Mode, string> = {
  normal: "常规",
  high_log: "日志激增",
  idle_audit: "空闲审计",
  yield: "让行",
};

export const modeDescription: Record<Mode, string> = {
  normal: "按常规计划采集与分析",
  high_log: "检测到错误或日志激增，正在深度分析",
  idle_audit: "处于空闲窗口，进行历史与安全审计",
  yield: "主机繁忙，AI 与深度任务已暂停",
};

export const modeTone: Record<Mode, BadgeTone> = {
  normal: "success",
  high_log: "warning",
  idle_audit: "info",
  yield: "neutral",
};

export const severityLabel: Record<Severity, string> = { critical: "严重", warning: "警告", info: "提示" };
export const severityTone: Record<Severity, BadgeTone> = { critical: "danger", warning: "warning", info: "info" };

export const findingSeverityLabel: Record<FindingSeverity, string> = {
  critical: "严重", high: "高", medium: "中", low: "低", info: "信息",
};
export const findingSeverityTone: Record<FindingSeverity, BadgeTone> = {
  critical: "danger", high: "danger", medium: "warning", low: "neutral", info: "info",
};
export const findingSeverityOrder: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

export const findingCategoryLabel: Record<string, string> = {
  port: "端口", login: "登录", update: "更新", kernel: "内核", network: "网络",
  db: "数据库", container: "容器", config: "配置", nginx: "nginx", perf: "性能",
};

export const reportKindLabel: Record<ReportKind, string> = {
  hourly: "小时报告", daily: "日报", incident: "事件报告", audit: "审计报告", custom: "自定义任务",
};

export const runStatusLabel: Record<AgentRunStatus, string> = {
  running: "运行中", succeeded: "成功", failed: "失败", fallback: "规则兜底", cancelled: "已取消",
};
export const runStatusTone: Record<AgentRunStatus, BadgeTone> = {
  running: "info", succeeded: "success", failed: "danger", fallback: "warning", cancelled: "neutral",
};

export const stepKindLabel: Record<AgentStep["kind"], string> = {
  user: "用户", tool_call: "工具调用", tool_result: "工具结果", message: "消息", error: "错误",
};

/** Run / conversation kinds: report kinds, chat, and scheduled task kinds. */
export const taskKindLabel: Record<string, string> = {
  hourly: "小时巡检", daily: "每日简报", incident: "事件分析", audit: "深度审计", chat: "对话",
  log_scan: "日志扫描", security_check: "安全体检", package_advice: "包更新建议", custom: "自定义任务",
};

export const confidenceLabel: Record<Confidence, string> = { high: "高置信度", medium: "中置信度", low: "低置信度" };
export const confidenceTone: Record<Confidence, BadgeTone> = { high: "info", medium: "neutral", low: "neutral" };

export const priorityLabel: Record<Priority, string> = { high: "高优先级", medium: "中优先级", low: "低优先级" };
export const priorityTone: Record<Priority, BadgeTone> = { high: "danger", medium: "warning", low: "neutral" };

export const categoryLabel: Record<RecommendationCategory, string> = {
  code: "代码", config: "配置", infra: "基础设施", database: "数据库", security: "安全",
};

export const containerStateLabel: Record<string, string> = {
  running: "运行中", exited: "已退出", restarting: "重启中", paused: "已暂停", created: "已创建", dead: "已失效",
};
export const containerStateTone: Record<string, BadgeTone> = {
  running: "success", exited: "neutral", restarting: "warning", paused: "neutral", created: "neutral", dead: "danger",
};

export const healthLabel: Record<string, string> = { healthy: "健康", unhealthy: "不健康", starting: "启动中" };

export const logLevelLabel: Record<string, string> = { error: "错误", warning: "警告", info: "信息", slow: "慢查询" };
export const logLevelTone: Record<string, BadgeTone> = { error: "danger", warning: "warning", info: "neutral", slow: "info" };

export const logKindLabel: Record<string, string> = {
  php_error: "PHP 错误", php_slow: "PHP 慢日志", nginx_access: "Nginx 访问", nginx_error: "Nginx 错误",
  node: "Node", mysql_slow: "MySQL 慢查询", generic: "通用", docker: "Docker",
};

export const dimensionLabel: Record<string, string> = {
  cpu: "CPU", memory: "内存", disk: "磁盘", logs: "日志", security: "安全", containers: "容器", database: "数据库",
};

export const triggerLabel: Record<string, string> = {
  schedule: "定时", manual: "手动", alert: "告警", mode: "模式切换",
  user: "用户", task: "自动任务", burst: "日志突增",
};

export const alertSourceLabel: Record<string, string> = {
  host: "主机", logs: "日志", containers: "容器", security: "安全", db: "数据库", agent: "Agent",
};

export const generatedByLabel: Record<"ai" | "rules", string> = { ai: "AI", rules: "规则" };

export function lookup(map: Record<string, string>, key: string | null | undefined): string {
  if (key == null) return "-";
  return map[key] ?? key;
}

export function lookupTone(map: Record<string, BadgeTone>, key: string | null | undefined): BadgeTone {
  return (key != null && map[key]) || "neutral";
}
