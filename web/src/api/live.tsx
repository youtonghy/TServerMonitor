// One shared EventSource on /api/v1/stream (or the mock stream), exposed through a context.
// The store keeps a rolling buffer of the last 360 metric samples for realtime charts.
import { createContext, useContext, useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { getToken, notifyUnauthorized, onTokenChange, streamUrl } from "./client";
import type { ContainerEventItem, HostMetrics, ModeState, StreamEventMap, StreamEventName } from "./types";

export const METRIC_BUFFER = 360;
const EVENTS: StreamEventName[] = ["metrics", "containers", "alert", "mode", "agent", "agent_delta", "report", "settings", "package_job", "ops_job", "ops_pending"];

export type ConnectionState = "connecting" | "open" | "closed";

interface LiveState {
  connection: ConnectionState;
  metrics: HostMetrics[];
  containers: ContainerEventItem[] | null;
  mode: ModeState | null;
}

type Handler<K extends StreamEventName> = (data: StreamEventMap[K]) => void;

class LiveStore {
  private state: LiveState = { connection: "connecting", metrics: [], containers: null, mode: null };
  private listeners = new Set<() => void>();
  private handlers = new Map<StreamEventName, Set<Handler<StreamEventName>>>();

  getState = () => this.state;

  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  on<K extends StreamEventName>(event: K, handler: Handler<K>): () => void {
    let set = this.handlers.get(event);
    if (!set) {
      set = new Set();
      this.handlers.set(event, set);
    }
    set.add(handler as Handler<StreamEventName>);
    return () => set.delete(handler as Handler<StreamEventName>);
  }

  setConnection(connection: ConnectionState) {
    if (this.state.connection === connection) return;
    this.update({ connection });
  }

  dispatch<K extends StreamEventName>(event: K, data: StreamEventMap[K]) {
    if (event === "metrics") {
      const sample = data as HostMetrics;
      const prev = this.state.metrics;
      // Drop out-of-order or duplicate samples; charts need ascending time.
      if (!prev.length || sample.ts > prev[prev.length - 1].ts) {
        const next = prev.length >= METRIC_BUFFER ? prev.slice(prev.length - METRIC_BUFFER + 1) : prev.slice();
        next.push(sample);
        this.update({ metrics: next });
      }
    } else if (event === "containers") {
      this.update({ containers: data as ContainerEventItem[] });
    } else if (event === "mode") {
      this.update({ mode: data as ModeState });
    }
    this.handlers.get(event)?.forEach(handler => {
      try {
        handler(data);
      } catch (error) {
        console.error(`处理 ${event} 事件失败`, error);
      }
    });
  }

  private update(patch: Partial<LiveState>) {
    this.state = { ...this.state, ...patch };
    this.listeners.forEach(listener => listener());
  }
}

const LiveContext = createContext<LiveStore | null>(null);

/** Opens the stream once for the whole app and reconnects when the token changes. */
export function LiveProvider({ children }: { children: ReactNode }) {
  const [store] = useState(() => new LiveStore());
  const [tokenVersion, setTokenVersion] = useState(0);

  useEffect(() => onTokenChange(() => setTokenVersion(v => v + 1)), []);

  useEffect(() => {
    if (import.meta.env.VITE_MOCK === "1") {
      let stop: (() => void) | null = null;
      let cancelled = false;
      import("./mock").then(module => {
        if (cancelled) return;
        store.setConnection("open");
        stop = module.startMockStream((event, data) => store.dispatch(event, data));
      }).catch(error => {
        console.error("无法加载模拟数据流", error);
        store.setConnection("closed");
      });
      return () => {
        cancelled = true;
        stop?.();
      };
    }

    let source: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;
    let disposed = false;

    const connect = () => {
      store.setConnection("connecting");
      source = new EventSource(streamUrl());
      source.onopen = () => {
        attempt = 0;
        store.setConnection("open");
      };
      source.onerror = () => {
        // The browser retries on its own while CONNECTING; a CLOSED source (for example a 401) needs a manual retry.
        if (!source || source.readyState !== EventSource.CLOSED) {
          store.setConnection("connecting");
          return;
        }
        store.setConnection("closed");
        source = null;
        if (disposed) return;
        attempt += 1;
        // A closed stream with no token often means the daemon wants one; ask once, then keep retrying slowly.
        if (attempt === 1 && !getToken()) probeAuth();
        retry = setTimeout(connect, Math.min(30_000, 2_000 * 2 ** Math.min(attempt, 4)));
      };
      for (const event of EVENTS) {
        source.addEventListener(event, message => {
          try {
            store.dispatch(event, JSON.parse((message as MessageEvent<string>).data));
          } catch (error) {
            console.error(`无法解析 ${event} 事件`, error);
          }
        });
      }
    };

    connect();
    return () => {
      disposed = true;
      if (retry) clearTimeout(retry);
      source?.close();
    };
  }, [store, tokenVersion]);

  return <LiveContext.Provider value={store}>{children}</LiveContext.Provider>;
}

/** EventSource hides the status code, so a cheap request tells whether the stream failed on auth. */
function probeAuth() {
  fetch("/api/v1/status", { headers: { Accept: "application/json" } })
    .then(response => {
      if (response.status === 401) notifyUnauthorized();
    })
    .catch(() => {
      // Offline: the stream retry loop handles it.
    });
}

function useStore(): LiveStore {
  const store = useContext(LiveContext);
  if (!store) throw new Error("LiveProvider is missing");
  return store;
}

function useLiveSelector<T>(select: (state: LiveState) => T): T {
  const store = useStore();
  return useSyncExternalStore(store.subscribe, () => select(store.getState()));
}

const selectMetrics = (s: LiveState) => s.metrics;
const selectConnection = (s: LiveState) => s.connection;
const selectContainers = (s: LiveState) => s.containers;
const selectMode = (s: LiveState) => s.mode;

/** Rolling buffer of the most recent HostMetrics samples, oldest first. */
export const useLiveMetrics = () => useLiveSelector(selectMetrics);
export const useConnection = () => useLiveSelector(selectConnection);
export const useLiveContainers = () => useLiveSelector(selectContainers);
export const useLiveMode = () => useLiveSelector(selectMode);

/** Subscribes to one SSE event type. The handler can change between renders without resubscribing. */
export function useStreamEvent<K extends StreamEventName>(event: K, handler: Handler<K>) {
  const store = useStore();
  const ref = useRef(handler);
  useEffect(() => {
    ref.current = handler;
  });
  useEffect(() => store.on(event, data => ref.current(data)), [store, event]);
}
