import { useMemo, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type Finding } from "../api";
import { capabilities, useAuth } from "../auth";
import { Async, Badge, ErrorBox, Section, SEVERITY_RANK, fmtDate, useAction, useAsync } from "../ui";

type SortKey = "severity" | "risk" | "status" | "title" | "last_seen";

function compare(a: Finding, b: Finding, key: SortKey): number {
  switch (key) {
    case "severity":
      return (SEVERITY_RANK[a.severity] ?? 0) - (SEVERITY_RANK[b.severity] ?? 0);
    case "risk":
      return (a.risk_score ?? -1) - (b.risk_score ?? -1);
    case "status":
      return a.status.localeCompare(b.status);
    case "title":
      return a.title.localeCompare(b.title);
    case "last_seen":
      return Date.parse(a.last_seen) - Date.parse(b.last_seen);
  }
}

/** Sortable findings table. Sorting is client-side over what the API returned. */
export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [key, setKey] = useState<SortKey>("severity");
  const [desc, setDesc] = useState(true);
  const sorted = useMemo(() => {
    const out = [...findings].sort((a, b) => compare(a, b, key));
    return desc ? out.reverse() : out;
  }, [findings, key, desc]);

  function header(label: string, k: SortKey) {
    const active = key === k;
    return (
      <th aria-sort={active ? (desc ? "descending" : "ascending") : "none"}>
        <button
          className="link"
          onClick={() => {
            if (active) setDesc(!desc);
            else {
              setKey(k);
              setDesc(k !== "title");
            }
          }}
        >
          {label}
          {active ? (desc ? " ▼" : " ▲") : ""}
        </button>
      </th>
    );
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {header("Severity", "severity")}
            {header("Title", "title")}
            <th>Asset</th>
            {header("Status", "status")}
            {header("Risk", "risk")}
            {header("Last seen", "last_seen")}
          </tr>
        </thead>
        <tbody>
          {sorted.map((f) => (
            <tr key={f.id}>
              <td>
                <Badge value={f.severity} />
              </td>
              <td>
                <Link to={`/findings/${f.id}`}>{f.title}</Link>
              </td>
              <td className="mono">{f.asset_identifier}</td>
              <td>
                <Badge value={f.status} />
              </td>
              <td>{f.risk_score === null ? "—" : f.risk_score.toFixed(1)}</td>
              <td>{fmtDate(f.last_seen)}</td>
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

  return (
    <>
      <h1>Findings</h1>
      <div className="filters" role="search" aria-label="Filter findings">
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
        {assessment && (
          <button className="secondary" onClick={() => set("assessment", "")}>
            Clear assessment filter
          </button>
        )}
      </div>
      <Async state={findings}>
        {(list) =>
          list.length === 0 ? (
            <p className="empty">
              No findings{status || severity || assessment ? " match these filters" : " yet"}. Findings appear
              only when a scanner actually observes something during an assessment.
            </p>
          ) : (
            <FindingsTable findings={list} />
          )
        }
      </Async>
    </>
  );
}

function BreakdownValue({ value }: { value: unknown }) {
  if (Array.isArray(value)) return <>{value.length ? value.join("; ") : "—"}</>;
  if (value === null || value === undefined) return <>—</>;
  return <>{String(value)}</>;
}

function OverrideForm({ findingId, onDone }: { findingId: string; onDone: () => void }) {
  const [status, setStatus] = useState<"confirmed" | "rejected">("confirmed");
  const [reason, setReason] = useState("");
  const action = useAction();

  async function submit(e: FormEvent) {
    e.preventDefault();
    const done = await action.run(() => api.overrideFinding(findingId, status, reason.trim()));
    if (done) onDone();
  }

  return (
    <form onSubmit={submit} className="form" aria-label="Analyst override">
      <p className="muted small">
        An analyst override is recorded in the audit log with your name and the reason. It only works
        where the finding's lifecycle allows it.
      </p>
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
      <button type="submit" disabled={action.busy}>
        Apply override
      </button>
    </form>
  );
}

export function FindingDetailPage() {
  const { id = "" } = useParams();
  const { user } = useAuth();
  const can = capabilities(user?.role);
  const finding = useAsync(() => api.finding(id), [id]);

  return (
    <>
      <p>
        <Link to="/findings">← Findings</Link>
      </p>
      <Async state={finding}>
        {(f) => (
          <>
            <h1>{f.title}</h1>
            <Section title="Summary">
              <dl className="facts">
                <dt>Severity</dt>
                <dd>
                  <Badge value={f.severity} />
                </dd>
                <dt>Status</dt>
                <dd>
                  <Badge value={f.status} />
                </dd>
                <dt>Confidence</dt>
                <dd>{f.confidence.toFixed(2)}</dd>
                <dt>Asset</dt>
                <dd className="mono">{f.asset_identifier}</dd>
                <dt>Component</dt>
                <dd>{f.affected_component ?? "—"}</dd>
                <dt>Source</dt>
                <dd>{f.source}</dd>
                <dt>First / last seen</dt>
                <dd>
                  {fmtDate(f.first_seen)} / {fmtDate(f.last_seen)}
                </dd>
                <dt>Assessment</dt>
                <dd>
                  <Link to={`/assessments/${f.assessment_id}`}>open</Link>
                </dd>
              </dl>
              {f.description && <p>{f.description}</p>}
            </Section>
            <Section title="Risk">
              {f.risk_score === null ? (
                <p className="empty">Not scored: the deterministic risk step has not run for this finding.</p>
              ) : (
                <>
                  <p className="big">
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
                </>
              )}
            </Section>
            <Section title={`Evidence (${f.evidence.length})`}>
              {f.evidence.length === 0 ? (
                <p className="empty">No evidence is attached to this finding.</p>
              ) : (
                f.evidence.map((ev) => (
                  <div className="subcard" key={ev.id}>
                    <p className="muted small">
                      <Badge value={ev.kind} /> captured {fmtDate(ev.captured_at)} · tool execution{" "}
                      <span className="mono">{ev.tool_execution_id}</span>
                    </p>
                    {/* Evidence is untrusted text from a target: rendered as text only. */}
                    <pre>{ev.excerpt}</pre>
                  </div>
                ))
              )}
            </Section>
            {can.write && (
              <Section title="Analyst override">
                <OverrideForm findingId={f.id} onDone={finding.reload} />
              </Section>
            )}
          </>
        )}
      </Async>
    </>
  );
}
