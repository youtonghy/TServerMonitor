import { useCallback, useSyncExternalStore } from "react";
import type { Theme } from "@/components/arc/theme-switch/theme-switch";

const KEY = "tsm_theme";
const listeners = new Set<() => void>();

/** Dark by default; light only when the person chose it. index.html applies the stored value before first paint. */
export function readTheme(): Theme {
  try {
    return localStorage.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

function apply(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

export function setTheme(theme: Theme) {
  try {
    localStorage.setItem(KEY, theme);
  } catch (error) {
    console.error("无法保存主题设置", error);
  }
  apply(theme);
  listeners.forEach(listener => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useTheme(): [Theme, (theme: Theme) => void] {
  const theme = useSyncExternalStore(subscribe, readTheme);
  const set = useCallback((next: Theme) => setTheme(next), []);
  return [theme, set];
}
