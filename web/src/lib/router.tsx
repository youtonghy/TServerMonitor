// A small hash router. Hash URLs need no server-side SPA fallback, so the embedded build works from any path.
import { useSyncExternalStore, type AnchorHTMLAttributes } from "react";

function subscribe(onChange: () => void) {
  window.addEventListener("hashchange", onChange);
  return () => window.removeEventListener("hashchange", onChange);
}

function currentPath(): string {
  const raw = window.location.hash.replace(/^#/, "");
  return raw.startsWith("/") ? raw : "/";
}

export interface Route { path: string; segments: string[]; params: URLSearchParams }

let cached: { hash: string; route: Route } | null = null;
function getRoute(): Route {
  const hash = window.location.hash;
  if (cached && cached.hash === hash) return cached.route;
  const full = currentPath();
  const [pathname, search = ""] = full.split("?");
  const route = { path: pathname, segments: pathname.split("/").filter(Boolean).map(decodeURIComponent), params: new URLSearchParams(search) };
  cached = { hash, route };
  return route;
}

export function useRoute(): Route {
  return useSyncExternalStore(subscribe, getRoute);
}

export function navigate(to: string, options: { replace?: boolean } = {}) {
  const hash = `#${to}`;
  if (options.replace) window.location.replace(hash);
  else window.location.hash = to;
}

export function href(to: string): string {
  return `#${to}`;
}

type LinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href"> & { to: string };

/** A real link (open in new tab works), routed through the hash. */
export function Link({ to, ...props }: LinkProps) {
  return <a href={href(to)} {...props} />;
}
