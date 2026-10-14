import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import { ApiError } from "./api";

/* ------------------------------------------------------------------ data hooks */

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

/** Runs a mutation, tracking busy + error state. `busy` blocks duplicate submissions. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    if (inFlight.current) return undefined;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (err) {
      setError(errorMessage(err));
      return undefined;
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }, []);
  return { busy, error, run, clear: () => setError(null) };
}

/* ------------------------------------------------------------------ icons */

const ICONS: Record<string, ReactNode> = {
  shield: <path d="M12 3 4 6v6c0 4.5 3.2 8 8 9 4.8-1 8-4.5 8-9V6z" />,
  overview: (
    <>
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </>
  ),
  target: (
    <>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="5" />
      <circle cx="12" cy="12" r="1" />
    </>
  ),
  activity: <path d="M22 12h-4l-3 9L9 3l-3 9H2" />,
  findings: (
    <>
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
      <path d="M12 9v4M12 17h.01" />
    </>
  ),
  audit: (
    <>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <path d="M14 2v6h6M8 13h8M8 17h5" />
    </>
  ),
  system: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="1.5" />
      <rect x="3" y="13" width="18" height="7" rx="1.5" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </>
  ),
  menu: <path d="M4 6h16M4 12h16M4 18h16" />,
  close: <path d="M18 6 6 18M6 6l12 12" />,
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </>
  ),
  chevron: <path d="m9 6 6 6-6 6" />,
  logout: <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />,
  check: <path d="M20 6 9 17l-5-5" />,
  "check-circle": (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="m8 12.5 3 3 5-6" />
    </>
  ),
  "x-circle": (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="m15 9-6 6M9 9l6 6" />
    </>
  ),
  octagon: (
    <>
      <path d="M8 2h8l6 6v8l-6 6H8l-6-6V8z" />
      <path d="M12 8v5M12 16h.01" />
    </>
  ),
  triangle: <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />,
  diamond: <path d="M12 2.5 21.5 12 12 21.5 2.5 12z" />,
  circle: <circle cx="12" cy="12" r="8" />,
  dot: <circle cx="12" cy="12" r="3" />,
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  loader: <path d="M21 12a9 9 0 1 1-6.2-8.55" />,
  minus: <path d="M5 12h14" />,
};

export function Icon({ name, size = 16 }: { name: string; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICONS[name] ?? ICONS.circle}
    </svg>
  );
}

/* ------------------------------------------------------------------ badges */

export type Tone = "critical" | "high" | "medium" | "low" | "info" | "ok" | "neutral";

/** Status/severity vocabulary → tone + icon. The icon and the text always carry the meaning; colour only reinforces. */
const BADGES: Record<string, { tone: Tone; icon: string; pulse?: boolean }> = {
  // severity / impact
  critical: { tone: "critical", icon: "octagon" },
  high: { tone: "high", icon: "triangle" },
  medium: { tone: "medium", icon: "diamond" },
  low: { tone: "low", icon: "circle" },
  info: { tone: "info", icon: "info" },
  // lifecycle
  pending: { tone: "neutral", icon: "clock" },
  queued: { tone: "neutral", icon: "clock" },
  running: { tone: "low", icon: "loader", pulse: true },
  completed: { tone: "ok", icon: "check-circle" },
  succeeded: { tone: "ok", icon: "check-circle" },
  completed_with_errors: { tone: "high", icon: "triangle" },
  failed: { tone: "critical", icon: "x-circle" },
  cancelled: { tone: "neutral", icon: "minus" },
  // findings
  discovered: { tone: "neutral", icon: "dot" },
  suspected: { tone: "medium", icon: "diamond" },
  investigating: { tone: "low", icon: "search" },
  confirmed: { tone: "ok", icon: "check-circle" },
  rejected: { tone: "neutral", icon: "x-circle" },
  reported: { tone: "info", icon: "check" },
  // authorization
  approved: { tone: "ok", icon: "check-circle" },
  revoked: { tone: "critical", icon: "x-circle" },
  expired: { tone: "high", icon: "clock" },
  // attack-path evidence levels (a weaker level must never look like a confirmed one)
  observed: { tone: "low", icon: "circle" },
  inferred: { tone: "medium", icon: "diamond" },
  potential: { tone: "high", icon: "triangle" },
  verified: { tone: "ok", icon: "check-circle" },
  // audit outcomes
  success: { tone: "ok", icon: "check-circle" },
  denied: { tone: "critical", icon: "x-circle" },
  failure: { tone: "critical", icon: "x-circle" },
};

export function badgeSpec(value: string): { tone: Tone; icon: string; pulse?: boolean } {
  return BADGES[value] ?? { tone: "neutral", icon: "circle" };
}

export function Badge({ value }: { value: string }) {
  const spec = badgeSpec(value);
  return (
    <span className={`badge tone-${spec.tone}`}>
      <span className={spec.pulse ? "pulse" : undefined}>
        <Icon name={spec.icon} size={12} />
      </span>
      {value.replace(/_/g, " ")}
    </span>
  );
}

/* ------------------------------------------------------------------ feedback */

export function Notice({ kind, children }: { kind: "info" | "warn" | "ok"; children: ReactNode }) {
  const icon = kind === "ok" ? "check-circle" : kind === "warn" ? "triangle" : "info";
  return (
    <div className={`alert ${kind}`}>
      <Icon name={icon} />
      <div className="alert-body">{children}</div>
    </div>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="alert error" role="alert">
      <Icon name="octagon" />
      <div className="alert-body">
        {message}
        {onRetry && (
          <>
            {" "}
            <button className="link" onClick={onRetry}>
              Retry
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Skeleton() {
  return (
    <div className="skeleton" role="status" aria-busy="true">
      <span className="sr-only">Loading…</span>
      <i />
      <i />
      <i />
    </div>
  );
}

/** Renders loading / error / empty / content for an async list or object. */
export function Async<T>({
  state,
  empty,
  emptyContent,
  children,
}: {
  state: AsyncState<T>;
  empty?: (data: T) => boolean;
  emptyContent?: ReactNode;
  children: (data: T) => ReactNode;
}) {
  if (state.error) return <ErrorBox message={state.error} onRetry={state.reload} />;
  if (state.loading && state.data === undefined) return <Skeleton />;
  if (state.data === undefined) return null;
  if (empty?.(state.data)) return <>{emptyContent ?? <EmptyState title="Nothing here yet." />}</>;
  return <>{children(state.data)}</>;
}

/* ------------------------------------------------------------------ toasts */

interface ToastItem {
  id: number;
  kind: "ok" | "error" | "info";
  message: string;
}
const ToastContext = createContext<((kind: ToastItem["kind"], message: string) => void) | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const next = useRef(0);
  const push = useCallback((kind: ToastItem["kind"], message: string) => {
    const id = ++next.current;
    setItems((list) => [...list, { id, kind, message }]);
    setTimeout(() => setItems((list) => list.filter((t) => t.id !== id)), 6000);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`alert ${t.kind}`}>
            <Icon name={t.kind === "ok" ? "check-circle" : t.kind === "error" ? "octagon" : "info"} />
            <div className="alert-body">{t.message}</div>
            <button
              className="ghost small"
              aria-label="Dismiss notification"
              onClick={() => setItems((list) => list.filter((x) => x.id !== t.id))}
            >
              <Icon name="close" size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

/** `toast("ok", "Saved")`. A no-op outside a provider so isolated components stay testable. */
export function useToast() {
  return useContext(ToastContext) ?? (() => undefined);
}

/* ------------------------------------------------------------------ dialog */

const FOCUSABLE = "button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled)";

/** Modal confirmation for consequential actions. Focus starts on Cancel; Escape and backdrop cancel. */
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  danger,
  busy,
  onConfirm,
  onCancel,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const titleId = useId();
  const ref = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    cancelRef.current?.focus();
    return () => previous?.focus();
  }, []);

  function onKeyDown(e: KeyboardEvent) {
    if (e.key === "Escape" && !busy) {
      e.stopPropagation();
      onCancel();
      return;
    }
    if (e.key !== "Tab" || !ref.current) return;
    const items = Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (items.length === 0) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  return (
    <div className="dialog-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onCancel()}>
      <div ref={ref} className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} onKeyDown={onKeyDown}>
        <h2 id={titleId}>{title}</h2>
        <div className="muted">{children}</div>
        <div className="row">
          <button ref={cancelRef} className="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button className={danger ? "danger solid" : undefined} onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ layout */

export function useDocumentTitle(title: string) {
  useEffect(() => {
    document.title = `${title} · OffensiveX`;
  }, [title]);
}

export function PageHeader({
  title,
  sub,
  badge,
  actions,
}: {
  title: string;
  sub?: ReactNode;
  badge?: ReactNode;
  actions?: ReactNode;
}) {
  useDocumentTitle(title);
  return (
    <header className="page-head">
      <div>
        <div className="title-row">
          <h1>{title}</h1>
          {badge}
        </div>
        {sub && <p className="sub">{sub}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function Panel({
  title,
  actions,
  flush,
  nested,
  children,
}: {
  title?: string;
  actions?: ReactNode;
  flush?: boolean;
  nested?: boolean;
  children: ReactNode;
}) {
  return (
    <section className={`panel${nested ? " nested" : ""}`}>
      {(title || actions) && (
        <header className="panel-head">
          {title && <h2>{title}</h2>}
          {actions}
        </header>
      )}
      <div className={`panel-body${flush ? " flush" : ""}`}>{children}</div>
    </section>
  );
}

export function Stats({ items }: { items: { label: string; value: ReactNode; hint?: ReactNode }[] }) {
  return (
    <dl className="stats">
      {items.map((s) => (
        <div className="stat" key={s.label}>
          <dt>{s.label}</dt>
          <dd>{s.value}</dd>
          {s.hint && <div className="hint">{s.hint}</div>}
        </div>
      ))}
    </dl>
  );
}

export function SearchInput({
  value,
  onChange,
  label,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  placeholder?: string;
}) {
  return (
    <div className="search" role="search">
      <Icon name="search" />
      <input
        type="search"
        aria-label={label}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

export function Progress({
  value,
  max,
  label,
  tone,
}: {
  value: number;
  max: number;
  label: string;
  tone?: "failed" | "done";
}) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div
      className={`progress${tone ? ` ${tone}` : ""}`}
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={value}
    >
      <i style={{ width: `${pct}%` }} />
    </div>
  );
}

/** Accessible tab list with arrow-key navigation. Panels use id `panel-<id>` and `aria-labelledby="tab-<id>"`. */
export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
}: {
  tabs: { id: T; label: string; count?: number }[];
  value: T;
  onChange: (id: T) => void;
  label: string;
}) {
  function onKeyDown(e: KeyboardEvent) {
    const i = tabs.findIndex((t) => t.id === value);
    const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!step) return;
    e.preventDefault();
    const nextTab = tabs[(i + step + tabs.length) % tabs.length];
    onChange(nextTab.id);
    document.getElementById(`tab-${nextTab.id}`)?.focus();
  }
  return (
    <div className="tabs" role="tablist" aria-label={label} onKeyDown={onKeyDown}>
      {tabs.map((t) => (
        <button
          key={t.id}
          id={`tab-${t.id}`}
          role="tab"
          aria-selected={value === t.id}
          aria-controls={`panel-${t.id}`}
          tabIndex={value === t.id ? 0 : -1}
          onClick={() => onChange(t.id)}
        >
          {t.label}
          {t.count !== undefined ? ` (${t.count})` : ""}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ helpers */

export function fmtDate(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

export const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export function download(filename: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
