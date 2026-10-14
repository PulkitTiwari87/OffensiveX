import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError } from "./api";

export interface AsyncState<T> {
  data: T | undefined;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Runs `fn` on mount and whenever `deps` change; exposes loading/error/data. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const latest = useRef(0);

  useEffect(() => {
    const id = ++latest.current;
    setLoading(true);
    fn().then(
      (value) => {
        if (id !== latest.current) return; // a newer request superseded this one
        setData(value);
        setError(null);
        setLoading(false);
      },
      (err: unknown) => {
        if (id !== latest.current) return;
        setError(errorMessage(err));
        setLoading(false);
      },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { data, error, loading, reload };
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    return err.status === 403 ? `Not allowed: ${err.message}` : err.message;
  }
  return err instanceof Error ? err.message : "Something went wrong.";
}

/** Renders loading / error / empty / content for an async list or object. */
export function Async<T>({
  state,
  empty,
  children,
}: {
  state: AsyncState<T>;
  empty?: (data: T) => boolean;
  children: (data: T) => ReactNode;
}) {
  if (state.error) return <ErrorBox message={state.error} onRetry={state.reload} />;
  if (state.loading && state.data === undefined) return <p className="muted">Loading…</p>;
  if (state.data === undefined) return null;
  if (empty?.(state.data)) return <p className="empty">Nothing here yet.</p>;
  return <>{children(state.data)}</>;
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="alert error" role="alert">
      {message}
      {onRetry && (
        <button className="link" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Notice({ kind, children }: { kind: "info" | "warn" | "ok"; children: ReactNode }) {
  return <div className={`alert ${kind}`}>{children}</div>;
}

export function Badge({ value }: { value: string }) {
  return <span className={`badge b-${value}`}>{value.replace(/_/g, " ")}</span>;
}

export function fmtDate(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

export function Section({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="card">
      <header className="card-head">
        <h2>{title}</h2>
        {actions}
      </header>
      {children}
    </section>
  );
}

/** Runs a mutation, tracking busy + error state for a form or button. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (err) {
      setError(errorMessage(err));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, run, clear: () => setError(null) };
}

export const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function download(filename: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
