import { Link } from "react-router-dom";
import { api } from "../api";
import { Async, Badge, Notice, Section, fmtDate, useAsync } from "../ui";

function Counts({ counts, empty }: { counts: Record<string, number>; empty: string }) {
  const entries = Object.entries(counts);
  if (entries.length === 0) return <p className="empty">{empty}</p>;
  return (
    <ul className="counts">
      {entries.map(([key, n]) => (
        <li key={key}>
          <Badge value={key} /> <strong>{n}</strong>
        </li>
      ))}
    </ul>
  );
}

export function OverviewPage() {
  const overview = useAsync(api.overview, []);
  const system = useAsync(api.systemStatus, []);

  return (
    <>
      <h1>Overview</h1>
      <Async state={system}>
        {(s) =>
          !s.llm.enabled ? (
            <Notice kind="warn">
              No LLM is configured, so assessments can be created but not run. Set the{" "}
              <code>OFFENSIVEX_LLM_*</code> variables and restart the backend.
            </Notice>
          ) : (
            <Notice kind="info">
              Agents use <strong>{s.llm.provider}</strong> / <strong>{s.llm.model}</strong> ·
              private targets {s.allow_private_targets ? "allowed" : "blocked"} · self-approval{" "}
              {s.allow_self_approval ? "allowed" : "off"}
            </Notice>
          )
        }
      </Async>
      <Async state={overview}>
        {(o) => (
          <>
            <div className="grid">
              <Section title="Targets">
                <p className="big">{o.targets}</p>
                <Link to="/targets">Manage targets</Link>
              </Section>
              <Section title="Assessments by status">
                <Counts counts={o.assessments_by_status} empty="No assessments yet." />
              </Section>
              <Section title="Findings by severity">
                <Counts counts={o.findings_by_severity} empty="No findings yet." />
              </Section>
              <Section title="Findings by status">
                <Counts counts={o.findings_by_status} empty="No findings yet." />
              </Section>
            </div>
            <Section title="Recent assessments">
              {o.recent_assessments.length === 0 ? (
                <p className="empty">
                  Nothing has run yet. <Link to="/targets">Create a target</Link>, get its scope
                  approved, then launch an assessment.
                </p>
              ) : (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Started</th>
                        <th>Findings</th>
                      </tr>
                    </thead>
                    <tbody>
                      {o.recent_assessments.map((a) => (
                        <tr key={a.id}>
                          <td>
                            <Link to={`/assessments/${a.id}`}>{a.target_name}</Link>
                          </td>
                          <td>
                            <Badge value={a.status} />
                          </td>
                          <td>{fmtDate(a.started_at)}</td>
                          <td>{a.finding_count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Section>
          </>
        )}
      </Async>
    </>
  );
}
