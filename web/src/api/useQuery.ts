import { useCallback, useEffect, useRef, useState, type DependencyList } from "react";
import { onAuthChange } from "./client";

export type Query<T> =
  | { status: "loading"; data: undefined; error: null; refreshing: boolean; reload: () => void; setData: (update: (prev: T | undefined) => T | undefined) => void }
  | { status: "error"; data: T | undefined; error: Error; refreshing: boolean; reload: () => void; setData: (update: (prev: T | undefined) => T | undefined) => void }
  | { status: "ready"; data: T; error: null; refreshing: boolean; reload: () => void; setData: (update: (prev: T | undefined) => T | undefined) => void };

interface Inner<T> { data: T | undefined; error: Error | null; pending: boolean }

/**
 * Runs `fetcher` when `deps` change and on demand. Earlier data stays on screen while a new request is
 * pending (`refreshing`), so changing a filter does not flash a skeleton. Responses that arrive after a
 * newer request started are ignored. Every query reruns after sign-in.
 */
export function useQuery<T>(fetcher: () => Promise<T>, deps: DependencyList, options: { refreshMs?: number } = {}): Query<T> {
  const [inner, setInner] = useState<Inner<T>>({ data: undefined, error: null, pending: true });
  const [nonce, setNonce] = useState(0);
  const seq = useRef(0);
  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  const reload = useCallback(() => setNonce(n => n + 1), []);
  const setData = useCallback((update: (prev: T | undefined) => T | undefined) => setInner(prev => ({ ...prev, data: update(prev.data) })), []);

  useEffect(() => onAuthChange(reload), [reload]);

  useEffect(() => {
    const id = ++seq.current;
    setInner(prev => (prev.pending && !prev.error ? prev : { ...prev, pending: true }));
    fetcherRef.current().then(
      data => {
        if (id === seq.current) setInner({ data, error: null, pending: false });
      },
      (error: unknown) => {
        if (id !== seq.current) return;
        const err = error instanceof Error ? error : new Error(String(error));
        setInner(prev => ({ data: prev.data, error: err, pending: false }));
      },
    );
    // deps are the caller's; fetcher is read through a ref.
  }, [...deps, nonce]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!options.refreshMs) return;
    const timer = setInterval(() => {
      if (!document.hidden) reload();
    }, options.refreshMs);
    return () => clearInterval(timer);
  }, [options.refreshMs, reload]);

  const base = { refreshing: inner.pending, reload, setData };
  if (inner.error && inner.data === undefined) return { ...base, status: "error", data: undefined, error: inner.error };
  if (inner.data === undefined) return { ...base, status: "loading", data: undefined, error: null };
  if (inner.error) return { ...base, status: "error", data: inner.data, error: inner.error };
  return { ...base, status: "ready", data: inner.data, error: null };
}
