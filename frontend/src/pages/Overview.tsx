import { Link } from "react-router-dom";
import { api, type Overview } from "../api";
import {
  Async,
  Badge,
  EmptyState,
  Icon,
  Notice,
  PageHeader,
  Panel,
  SEVERITY_ORDER,
  Stats,
  badgeSpec,
  fmtDate,
  useAsync,
} from "../ui";

const sum = (counts: Record<string, number>) => Object.values(counts).reduce((a, b) => a + b, 0);

/** Distribution bar plus a text legend: the legend carries the numbers, the bar is a visual aid only. */
function Distribution({ counts, order, empty }: { counts: Record<string, number>; order: readonly string[]; empty: string }) {
  const keys = [...order.filter((k) => counts[k]), ...Object.keys(counts).filter((k) => !order.includes(k) && counts[k])];
  if (keys.length === 0) return <EmptyState title={empty} />;
  return (
    <>
      <div className="segbar" aria-hidden="true">
        {keys.map((k) => (
          <i key={k} className={`tone-${badgeSpec(k).tone}`} style={{ flex: counts[k] }} />
        ))}
      </div>
      <ul className="legend">
        {keys.map((k) => (
          <li key={k}>
            <Badge value={k} />
            <span className="count">{counts[k]}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

function RecentAssessments({ items }: { items: Overview["recent_assessments"] }) {
  if (items.length === 0)
    return (
      <EmptyState title="Nothing has run yet.">
        <Link to="/targets">Create a target</Link>, get its scope approved, then launch an assessment.
      </EmptyState>
    );
  return (
    <div className="table-wrap">
      <table className="stack">
        <thead>
          <tr>
            <th>Target</th>
            <th>Status</th>
            <th>Started</th>
            <th className="num">Findings</th>
          </tr>
        </thead>
        <tbody>
          {items.map((a) => (
            <tr key={a.id}>
              <td className="title-cell" data-label="Target">
                <Link to={`/assessments/${a.id}`}>{a.target_name}</Link>
              </td>
              <td data-label="Status">
                <Badge value={a.status} />
              </td>
              <td data-label="Started">{fmtDate(a.started_at)}</td>
              <td className="num" data-label="Findings">
                {a.finding_count}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function OverviewPage() {
  const overview = useAsync(api.overview, []);
  const system = useAsync(api.systemStatus, []);

  return (
    <>
      <PageHeader title="Overview" sub="Current state of your authorized targets, assessments and findings." />
      <Async state={system}>
        {(s) =>
          !s.llm.enabled ? (
            <Notice kind="warn">
              No LLM is configured, so assessments can be created but not run. Set the <code>OFFENSIVEX_LLM_*</code>{" "}
              variables and restart the backend.
            </Notice>
          ) : (
            <Notice kind="info">
              Agents use <strong>{s.llm.provider}</strong> / <strong>{s.llm.model}</strong> · private targets{" "}
              {s.allow_private_targets ? "allowed" : "blocked"} · self-approval {s.allow_self_approval ? "allowed" : "off"}
            </Notice>
          )
        }
      </Async>
      <Async state={overview}>
        {(o) => {
          const totalFindings = sum(o.findings_by_severity);
          return (
            <>
              <Stats
                items={[
                  { label: "Targets", value: o.targets },
                  { label: "Running assessments", value: o.assessments_by_status.running ?? 0 },
                  { label: "Findings", value: totalFindings },
                  { label: "Confirmed", value: o.findings_by_status.confirmed ?? 0 },
                  {
                    label: "Critical + high",
                    value: (o.findings_by_severity.critical ?? 0) + (o.findings_by_severity.high ?? 0),
                  },
                ]}
              />
              <div className="cols">
                <Panel title="Findings by severity">
                  <Distribution counts={o.findings_by_severity} order={SEVERITY_ORDER} empty="No findings yet." />
                </Panel>
                <Panel title="Findings by status">
                  <Distribution
                    counts={o.findings_by_status}
                    order={["discovered", "suspected", "investigating", "confirmed", "rejected", "reported"]}
                    empty="No findings yet."
                  />
                </Panel>
                <Panel title="Assessments by status">
                  <Distribution
                    counts={o.assessments_by_status}
                    order={["running", "pending", "completed", "completed_with_errors", "failed", "cancelled"]}
                    empty="No assessments yet."
                  />
                </Panel>
              </div>
              <div style={{ height: "var(--s-4)" }} />
              <Panel
                title="Recent assessments"
                flush
                actions={
                  <Link to="/assessments" className="small">
                    View all <Icon name="chevron" size={12} />
                  </Link>
                }
              >
                <RecentAssessments items={o.recent_assessments} />
              </Panel>
            </>
          );
        }}
      </Async>
    </>
  );
}
