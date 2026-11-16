// Chinese-friendly formatting for bytes, rates, percentages, durations, and times.
// The dashboard is client-rendered only, so the browser time zone is used for display.

const LOCALE = "zh-CN";

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

function scaled(value: number, units: string[], base: number, digits: number): string {
  if (!Number.isFinite(value)) return "-";
  const sign = value < 0 ? "-" : "";
  let n = Math.abs(value);
  let i = 0;
  while (n >= base && i < units.length - 1) {
    n /= base;
    i += 1;
  }
  const fixed = i === 0 ? Math.round(n).toString() : n.toFixed(n >= 100 ? 0 : digits);
  return `${sign}${fixed} ${units[i]}`;
}

/** 1536 -> "1.5 KB" (binary multiples, labelled KB/MB/GB as most Chinese tools do). */
export function formatBytes(bytes: number, digits = 1): string {
  return scaled(bytes, BYTE_UNITS, 1024, digits);
}

/** Bytes per second -> "1.5 MB/s". */
export function formatRate(bps: number, digits = 1): string {
  return `${formatBytes(bps, digits)}/s`;
}

/** 42.345 -> "42.3%". */
export function formatPercent(pct: number, digits = 1): string {
  if (!Number.isFinite(pct)) return "-";
  return `${pct.toFixed(digits)}%`;
}

/** Ratio of used/total as a percentage, safe for a zero total. */
export function percentOf(used: number, total: number): number {
  return total > 0 ? (used / total) * 100 : 0;
}

const number = new Intl.NumberFormat(LOCALE, { maximumFractionDigits: 1 });
const compactNumber = new Intl.NumberFormat(LOCALE, { notation: "compact", maximumFractionDigits: 1 });

export function formatNumber(n: number): string {
  return Number.isFinite(n) ? number.format(n) : "-";
}

/** 12345 -> "1.2万". */
export function formatCompact(n: number): string {
  return Number.isFinite(n) ? compactNumber.format(n) : "-";
}

/** Seconds -> "3天 4小时", "5小时 12分钟", "8分钟", "42秒". */
export function formatDuration(totalSecs: number): string {
  if (!Number.isFinite(totalSecs) || totalSecs < 0) return "-";
  const s = Math.floor(totalSecs);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return h > 0 ? `${d}天 ${h}小时` : `${d}天`;
  if (h > 0) return m > 0 ? `${h}小时 ${m}分钟` : `${h}小时`;
  if (m > 0) return `${m}分钟`;
  return `${s}秒`;
}

const dateTime = new Intl.DateTimeFormat(LOCALE, {
  year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
});
const shortDateTime = new Intl.DateTimeFormat(LOCALE, {
  month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
});
const timeOnly = new Intl.DateTimeFormat(LOCALE, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const hourMinute = new Intl.DateTimeFormat(LOCALE, { hour: "2-digit", minute: "2-digit", hour12: false });
const monthDay = new Intl.DateTimeFormat(LOCALE, { month: "numeric", day: "numeric" });

/** "2026/11/16 18:30:05". */
export function formatDateTime(ms: number | null | undefined): string {
  return ms == null ? "-" : dateTime.format(ms);
}

/** "11/16 18:30". */
export function formatShortDateTime(ms: number | null | undefined): string {
  return ms == null ? "-" : shortDateTime.format(ms);
}

/** "18:30:05". */
export function formatTime(ms: number | null | undefined): string {
  return ms == null ? "-" : timeOnly.format(ms);
}

/** "18:30". */
export function formatHourMinute(ms: number): string {
  return hourMinute.format(ms);
}

/** "11月16日" style short date, "11/16" in zh-CN numeric form. */
export function formatMonthDay(ms: number): string {
  return monthDay.format(ms);
}

/** "刚刚", "5分钟前", "3小时前", "2天前", then an absolute date. */
export function formatRelative(ms: number | null | undefined, now: number): string {
  if (ms == null) return "-";
  const diff = Math.max(0, now - ms) / 1000;
  if (diff < 45) return "刚刚";
  if (diff < 3600) return `${Math.round(diff / 60)}分钟前`;
  if (diff < 86400) return `${Math.round(diff / 3600)}小时前`;
  if (diff < 86400 * 7) return `${Math.round(diff / 86400)}天前`;
  return formatShortDateTime(ms);
}

/** Axis tick label for a time series, picked by the span it covers. */
export function formatAxisTime(ms: number, spanMs: number): string {
  return spanMs > 2 * 86400_000 ? formatMonthDay(ms) : formatHourMinute(ms);
}

/** Elapsed time between two instants, for run durations. */
export function formatElapsed(start: number, end: number | null, now: number): string {
  return formatDuration(((end ?? now) - start) / 1000);
}
