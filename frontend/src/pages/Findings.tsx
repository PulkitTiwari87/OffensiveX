import { useMemo, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type Evidence, type Finding } from "../api";
import { capabilities, useAuth } from "../auth";
import {
  Async,
  Badge,
  ConfirmDialog,
  EmptyState,
  ErrorBox,
  Icon,
  Notice,
  PageHeader,
  Panel,
  SEVERITY_RANK,
  SearchInput,
  fmtDate,
  useAction,
  useAsync,
  useToast,
} from "../ui";

type SortKey = "severity" | "risk" | "confidence" | "status" | "title" | "last_seen";

function compare(a: Finding, b: Finding, key: SortKey): number {
  switch (key) {
    case "severity":
      return (SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0);
    case "risk":
      return (a.risk_score ?? -1) - (b.risk_score ?? -1);
    case "confidence":
      return a.confidence - b.confidence;
    case "status":
      return a.status.localeCompare(b.status);
    case "title":
      return a.title.localeCompare(b.title);
    case "last_seen":
      return Date.parse(a.last_seen) - Date.parse(b.last_seen);
  }
}

function Confidence({ value }: { value: number }) {
  return (
    <span className="confidence">
      <span className="progress" aria-hidden="true">
        <i style={{ width: `${Math.round(Math.min(Math.max(value, 0), 1) * 100)}%` }} />
      </span>
      {value.toFixed(2)}
    </span>
  );
}

/** Sortable findings table. Sorting is client-side over what the API returned. */
export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [key, setKey] = useState<SortKey>("severity");
  const [desc, setDesc] = useState(true);
  const sorted = useMemo(() => {
    const out = [...findings].sort((a, b) => compare(a, b, key));
    return desc ? out.reverse() : out;
  }, [findings, key, desc]);

  function header(label: string, k: SortKey, className?: string) {
    const active = key === k;
    return (
      <th className={className} aria-sort={active ? (desc ? "descending" : "ascending") : "none"}>
        <button
          className="sort"
          onClick={() => {
            if (active) setDesc(!desc);
            else {
              setKey(k);
              setDesc(k !== "title");
            }
          }}
        >
          {label}
          <span aria-hidden="true">{active ? (desc ? "▼" : "▲") : ""}</span>
        </button>
      </th>
    );
  }

  return (
    <div className="table-wrap">
      <table className="stack">
        <thead>
          <tr>
            {header("Severity", "severity")}
            {header("Title", "title")}
            <th>Asset</th>
            {header("Status", "status")}
            {header("Confidence", "confidence")}
            {header("Risk", "risk", "num")}
            {header("Last seen", "last_seen")}
          </tr>
        </thead>
        <tbody>
          {sorted.map((f) => (
            <tr key={f.id}>
              <td data-label="Severity">
                <Badge value={f.severity} />
              </td>
              <td className="title-cell" data-label="Title">
                <Link to={`/findings/${f.id}`}>{f.title}</Link>
              </td>
              <td className="mono" data-label="Asset">
                {f.asset_identifier}
              </td>
              <td data-label="Status">
                <Badge value={f.status} />
              </td>
              <td data-label="Confidence">
                <Confidence value={f.confidence} />
              </td>
              <td className="num" data-label="Risk">
                {f.risk_score === null ? "—" : f.risk_score.toFixed(1)}
              </td>
              <td data-label="Last seen">{fmtDate(f.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const STATUSES = ["discovered", "suspected", "investigating", "confirmed", "rejected", "reported"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const status = params.get("status") ?? "";
  const severity = params.get("severity") ?? "";
  const assessment = params.get("assessment") ?? "";
  const findings = useAsync(
    () =>
      api.findings({
        status: status || undefined,
        severity: severity || undefined,
        assessment_id: assessment || undefined,
      }),
    [status, severity, assessment],
  );

  const set = (name: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(name, value);
    else next.delete(name);
    setParams(next, { replace: true });
  };
  const filtered = !!(status || severity || assessment || query);
  const clear = () => {
    setQuery("");
    setParams(new URLSearchParams(), { replace: true });
  };

  const needle = query.trim().toLowerCase();
  const visible = (findings.data ?? []).filter(
    (f) =>
      !needle ||
      [f.title, f.asset_identifier, f.affected_component ?? "", f.source].some((s) => s.toLowerCase().includes(needle)),
  );

  return (
    <>
      <PageHeader title="Findings" sub="Observations recorded by assessments, with the evidence behind each one." />
      <div className="toolbar" role="group" aria-label="Filter findings">
        <SearchInput value={query} onChange={setQuery} label="Search findings" placeholder="Search title, asset, component" />
        <label>
          Status
          <select value={status} onChange={(e) => set("status", e.target.value)}>
            <option value="">all</option>
            {STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        <label>
          Severity
          <select value={severity} onChange={(e) => set("severity", e.target.value)}>
            <option value="">all</option>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        {filtered && (
          <button className="ghost" onClick={clear}>
            Clear filters
          </button>
        )}
        {findings.data && (
          <span className="result-count" aria-live="polite">
            {visible.length} of {findings.data.length} shown
          </span>
        )}
      </div>
      <Panel flush>
        <Async state={findings}>
          {(list) =>
            list.length === 0 ? (
              <EmptyState title={`No findings${status || severity || assessment ? " match these filters" : " yet"}.`}>
                Findings appear only when a scanner actually observes something during an assessment.
              </EmptyState>
            ) : visible.length === 0 ? (
              <EmptyState title="No findings match your search.">
                Search looks at the findings already loaded for the selected status and severity.
              </EmptyState>
            ) : (
              <FindingsTable findings={visible} />
            )
          }
        </Async>
      </Panel>
    </>
  );
}

function BreakdownValue({ value }: { value: unknown }) {
  if (Array.isArray(value)) return <>{value.length ? value.join("; ") : "—"}</>;
  if (value === null || value === undefined) return <>—</>;
  return <>{String(value)}</>;
}

function OverrideForm({ findingId, hasEvidence, onDone }: { findingId: string; hasEvidence: boolean; onDone: () => void }) {
  const [status, setStatus] = useState<"confirmed" | "rejected">("confirmed");
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(false);
  const action = useAction();
  const toast = useToast();

  function submit(e: FormEvent) {
    e.preventDefault();
    setConfirming(true);
  }
  async function apply() {
    const done = await action.run(() => api.overrideFinding(findingId, status, reason.trim()));
    setConfirming(false);
    if (done) {
      toast("ok", `Finding marked ${status}.`);
      setReason("");
      onDone();
    }
  }

  return (
    <form onSubmit={submit} className="form" aria-label="Analyst override">
      <p className="muted small">
        An analyst override is recorded in the audit log with your name and the reason. It only works where the
        finding's lifecycle allows it.
      </p>
      {!hasEvidence && status === "confirmed" && (
        <Notice kind="warn">This finding has no evidence attached, so the server will not let it be confirmed.</Notice>
      )}
      <label>
        Set status
        <select value={status} onChange={(e) => setStatus(e.target.value as "confirmed" | "rejected")}>
          <option>confirmed</option>
          <option>rejected</option>
        </select>
      </label>
      <label>
        Reason
        <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} />
      </label>
      {action.error && <ErrorBox message={action.error} />}
      <div>
        <button type="submit" disabled={action.busy}>
          Apply override
        </button>
      </div>
      {confirming && (
        <ConfirmDialog
          title={`Mark this finding ${status}?`}
          confirmLabel={`Mark ${status}`}
          danger={status === "rejected"}
          busy={action.busy}
          onConfirm={() => void apply()}
          onCancel={() => setConfirming(false)}
        >
          This overrides the automated lifecycle and is written to the audit log under your name.
        </ConfirmDialog>
      )}
    </form>
  );
}

function EvidenceItem({ ev, open }: { ev: Evidence; open: boolean }) {
  return (
    <details className="evidence" open={open}>
      <summary>
        <span className="chev" aria-hidden="true">
          <Icon name="chevron" size={14} />
        </span>
        <Badge value={ev.kind} />
        <span className="muted small">captured {fmtDate(ev.captured_at)}</span>
        <span className="faint small mono">tool execution {ev.tool_execution_id}</span>
      </summary>
      <div className="evidence-body">
        {/* Evidence is untrusted text from a target: rendered as text only. */}
        <pre>{ev.excerpt}</pre>
      </div>
    </details>
  );
}

export function FindingDetailPage() {
  const { id = "" } = useParams();
  const { user } = useAuth();
  const can = capabilities(user?.role);
  const finding = useAsync(() => api.finding(id), [id]);

  return (
    <Async state={finding}>
      {(f) => (
        <>
          <PageHeader
            title={f.title}
            badge={<Badge value={f.severity} />}
            sub={<span className="mono">{f.asset_identifier}</span>}
            actions={
              <Link className="btn secondary" to={`/assessments/${f.assessment_id}`}>
                Open assessment
              </Link>
            }
          />
          <div className="cols-2-1">
            <div>
              <Panel title={`Evidence (${f.evidence.length})`}>
                {f.evidence.length === 0 ? (
                  <EmptyState title="No evidence is attached to this finding." />
                ) : (
                  f.evidence.map((ev, i) => <EvidenceItem key={ev.id} ev={ev} open={i === 0} />)
                )}
              </Panel>
              {f.description && (
                <Panel title="Description">
                  <p>{f.description}</p>
                </Panel>
              )}
              {can.write && (
                <Panel title="Analyst override">
                  <OverrideForm findingId={f.id} hasEvidence={f.evidence.length > 0} onDone={finding.reload} />
                </Panel>
              )}
            </div>
            <div>
              <Panel title="Summary">
                <dl className="facts">
                  <dt>Status</dt>
                  <dd>
                    <Badge value={f.status} />
                  </dd>
                  <dt>Confidence</dt>
                  <dd>
                    <Confidence value={f.confidence} />
                  </dd>
                  <dt>Component</dt>
                  <dd>{f.affected_component ?? "—"}</dd>
                  <dt>Source</dt>
                  <dd>{f.source}</dd>
                  <dt>First seen</dt>
                  <dd>{fmtDate(f.first_seen)}</dd>
                  <dt>Last seen</dt>
                  <dd>{fmtDate(f.last_seen)}</dd>
                </dl>
              </Panel>
              <Panel title="Risk">
                {f.risk_score === null ? (
                  <p className="muted">Not scored: the deterministic risk step has not run for this finding.</p>
                ) : (
                  <div className="stack-gap">
                    <p className="score">
                      {f.risk_score.toFixed(2)} <small>/ 10</small>
                    </p>
                    {f.risk_breakdown && (
                      <dl className="facts">
                        {Object.entries(f.risk_breakdown).map(([k, v]) => (
                          <div key={k} className="fact-row">
                            <dt>{k.replace(/_/g, " ")}</dt>
                            <dd>
                              <BreakdownValue value={v} />
                            </dd>
                          </div>
                        ))}
                      </dl>
                    )}
                  </div>
                )}
              </Panel>
            </div>
          </div>
        </>
      )}
    </Async>
  );
}
