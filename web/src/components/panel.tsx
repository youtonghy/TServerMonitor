import { useEffect, useId, useState, type ReactNode } from "react";
import { Alert } from "@/components/arc/alert/alert";
import { Button } from "@/components/arc/button/button";
import { EmptyState } from "@/components/arc/empty-state/empty-state";
import { Skeleton } from "@/components/arc/skeleton/skeleton";
import { ApiError } from "@/api/client";
import type { Query } from "@/api/useQuery";
import styles from "./panel.module.css";

export function errorMessage(error: Error): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "需要访问令牌。请在弹出的对话框中输入令牌后重试。";
    if (error.status === 0) return error.message;
    if (error.status === 404) return "请求的数据不存在。";
    return `${error.message}（状态码 ${error.status}）`;
  }
  return error.message || "发生未知错误";
}

interface PanelProps {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  busy?: boolean;
  /** Removes the body padding, for tables that scroll edge to edge. */
  flush?: boolean;
}

/** A bordered region with a heading. One per data region; never nested. */
export function Panel({ title, description, actions, children, className, busy, flush }: PanelProps) {
  const id = useId();
  return (
    <section className={[styles.panel, className].filter(Boolean).join(" ")} aria-labelledby={id} aria-busy={busy || undefined}>
      <header className={styles.head}>
        <div className={styles.titles}>
          <h2 id={id} className={styles.title}>{title}</h2>
          {description && <p className={styles.description}>{description}</p>}
        </div>
        {actions && <div className={styles.actions}>{actions}</div>}
      </header>
      <div className={flush ? styles.flush : styles.body}>{children}</div>
    </section>
  );
}

interface QueryViewProps<T> {
  query: Query<T>;
  children: (data: T) => ReactNode;
  isEmpty?: (data: T) => boolean;
  empty?: { title: string; description: string; action?: ReactNode };
  skeletonLines?: number;
  errorTitle?: string;
  /** Minimum height of the loading skeleton, so the layout does not jump when data lands. */
  minHeight?: number;
}

/** Loading, error, empty, and ready states for one query. */
export function QueryView<T>({ query, children, isEmpty, empty, skeletonLines = 4, errorTitle = "数据加载失败", minHeight }: QueryViewProps<T>) {
  if (query.status === "loading") {
    return <div style={{ minHeight }} className={styles.skeleton}><Skeleton lines={skeletonLines} label="正在加载" /></div>;
  }
  if (query.status === "error" && query.data === undefined) {
    return (
      <Alert tone="danger" title={errorTitle}>
        <p className={styles.alertText}>{errorMessage(query.error)}</p>
        <Button variant="secondary" size="sm" onClick={query.reload} loading={query.refreshing}>重新加载</Button>
      </Alert>
    );
  }
  const data = query.data as T;
  return (
    <>
      {query.status === "error" && (
        <Alert tone="warning" title="数据可能已过期">
          <p className={styles.alertText}>{errorMessage(query.error)}</p>
          <Button variant="secondary" size="sm" onClick={query.reload} loading={query.refreshing}>重新加载</Button>
        </Alert>
      )}
      {isEmpty?.(data) && empty
        ? <EmptyState title={empty.title} description={empty.description} action={empty.action} />
        : children(data)}
    </>
  );
}

type SectionProps<T> = Omit<PanelProps, "children" | "busy"> & QueryViewProps<T>;

/** A panel whose body follows one query's states. */
export function Section<T>({ title, description, actions, className, flush, ...view }: SectionProps<T>) {
  return (
    <Panel title={title} description={description} actions={actions} className={className} flush={flush && view.query.status === "ready"} busy={view.query.status === "loading"}>
      <QueryView {...view} />
    </Panel>
  );
}

/** Current time that ticks, for relative timestamps. */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);
  return now;
}

/** A row of label and value pairs. */
export function Facts({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <dl className={styles.facts}>
      {items.map(item => (
        <div key={item.label} className={styles.fact}>
          <dt>{item.label}</dt>
          <dd>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Page heading row with optional tools on the right. */
export function PageHeader({ title, description, children }: { title: string; description?: string; children?: ReactNode }) {
  return (
    <header className={styles.pageHeader}>
      <div className={styles.titles}>
        <h1 className={styles.pageTitle}>{title}</h1>
        {description && <p className={styles.pageDescription}>{description}</p>}
      </div>
      {children && <div className={styles.tools}>{children}</div>}
    </header>
  );
}
