import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Assessment } from "../api";
import { capabilities, useAuth } from "../auth";
import { Async, Badge, ErrorBox, Notice, Section, fmtDate, useAction, useAsync } from "../ui";
import { FindingsTable } from "./Findings";

const STATUSES = ["running", "completed", "completed_with_errors", "failed", "cancelled"];

export function AssessmentsPage() {
  const [status, setStatus] = useState("");
  const list = useAsync(() => api.assessments({ status: status || undefined, limit: 100 }), [status]);

  return (
    <>
      <h1>Assessments</h1>
      <div className="filters">
        <label>
          Status
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">all</option>
            {STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
      </div>
      <Async state={list}>
        {(items) =>
          items.length === 0 ? (
            <p className="empty">
              No assessments{status ? " with this status" : " yet"}. Open a target to create one once its
              scope is approved.
            </p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Mode</th>
                    <th>Started</th>
                    <th>Finished</th>
                    <th>Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <Link to={`/assessments/${a.id}`}>{a.target_name}</Link>
                      </td>
                      <td>
                        <Badge value={a.status} />
                      </td>
                      <td>
                        {a.scan_mode}
                        {a.validation_enabled ? " + validation" : ""}
                      </td>
                      <td>{fmtDate(a.started_at)}</td>
                      <td>{fmtDate(a.finished_at)}</td>
                      <td>{a.finding_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </Async>
    </>
  );
}

function AgentRuns({ assessment }: { assessment: Assessment }) {
  const runs = [...assessment.agent_runs].sort((a, b) =>
    (a.created_at ?? "").localeCompare(b.created_at ?? ""),
  );
  const failures = runs.filter((r) => r.status === "failed");
  return (
    <>
      {failures.length > 0 && (
        <Notice kind="warn">
          {failures.length} agent run{failures.length > 1 ? "s" : ""} failed. The reason is shown on each
          failed row.
        </Notice>
      )}
      {runs.length === 0 ? (
        <p className="empty">No agent has run yet.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Agent</th>
                <th>Status</th>
                <th>Attempts</th>
                <th>Started</th>
                <th>Finished</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id} className={r.status === "failed" ? "row-failed" : undefined}>
                  <td>{r.agent_type}</td>
                  <td>
                    <Badge value={r.status} />
                  </td>
                  <td>{r.attempts}</td>
                  <td>{fmtDate(r.started_at)}</td>
                  <td>{fmtDate(r.finished_at)}</td>
                  <td>{r.error ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function ReportsPanel({ assessmentId, canGenerate }: { assessmentId: string; canGenerate: boolean }) {
  const reports = useAsync(() => api.reports(assessmentId), [assessmentId]);
  const action = useAction();

  async function generate() {
    const created = await action.run(() => api.generateReport(assessmentId, ["json", "markdown"]));
    if (created) reports.reload();
  }

  return (
    <>
      {canGenerate && (
        <p>
          <button onClick={generate} disabled={action.busy}>
            {action.busy ? "Generating…" : "Generate report (JSON + Markdown)"}
          </button>
        </p>
      )}
      {action.error && <ErrorBox message={action.error} />}
      <Async state={reports} empty={(r) => r.length === 0}>
        {(list) => (
          <ul>
            {list.map((r) => (
              <li key={r.id}>
                <Link to={`/reports/${r.id}`}>{fmtDate(r.generated_at)}</Link> · {r.formats.join(", ")}
              </li>
            ))}
          </ul>
        )}
      </Async>
    </>
  );
}

export function AssessmentDetailPage() {
  const { id = "" } = useParams();
  const { user } = useAuth();
  const can = capabilities(user?.role);
  const assessment = useAsync(() => api.assessment(id), [id]);
  const findings = useAsync(() => api.findings({ assessment_id: id }), [id]);
  const assets = useAsync(() => api.assets(id), [id]);
  const paths = useAsync(() => api.attackPaths(id), [id]);
  const control = useAction();

  const status = assessment.data?.status;
  const reloadAssessment = assessment.reload;
  const reloadFindings = findings.reload;
  const reloadAssets = assets.reload;
  const reloadPaths = paths.reload;

  // While the pipeline is running, keep the page current.
  useEffect(() => {
    if (status !== "running") return;
    const timer = setInterval(() => {
      reloadAssessment();
      reloadFindings();
      reloadAssets();
      reloadPaths();
    }, 3000);
    return () => clearInterval(timer);
  }, [status, reloadAssessment, reloadFindings, reloadAssets, reloadPaths]);

  const notStarted =
    assessment.data !== undefined &&
    assessment.data.status === "running" &&
    assessment.data.agent_runs.every((r) => r.status === "queued");

  async function start() {
    const done = await control.run(() => api.runAssessment(id));
    if (done) assessment.reload();
  }
  async function cancel() {
    const done = await control.run(() => api.cancelAssessment(id));
    if (done) assessment.reload();
  }

  return (
    <>
      <p>
        <Link to="/assessments">← Assessments</Link>
      </p>
      <h1>Assessment</h1>
      <Async state={assessment}>
        {(a) => (
          <>
            <Section
              title="Status"
              actions={
                can.write && notStarted ? (
                  <div className="row">
                    <button onClick={start} disabled={control.busy}>
                      Start run
                    </button>
                    <button className="secondary" onClick={cancel} disabled={control.busy}>
                      Cancel
                    </button>
                  </div>
                ) : undefined
              }
            >
              <dl className="facts">
                <dt>Status</dt>
                <dd>
                  <Badge value={a.status} />
                </dd>
                <dt>Target</dt>
                <dd>
                  <Link to={`/targets/${a.target_id}`}>open target</Link>
                </dd>
                <dt>Mode</dt>
                <dd>
                  {a.scan_mode}
                  {a.validation_enabled ? " + validation" : ""}
                </dd>
                <dt>Started / finished</dt>
                <dd>
                  {fmtDate(a.started_at)} / {fmtDate(a.finished_at)}
                </dd>
              </dl>
              {notStarted && <Notice kind="info">Created but not started. Starting it runs the agents against the authorized scope.</Notice>}
              {a.status === "running" && !notStarted && (
                <Notice kind="info">Running — this page refreshes every few seconds.</Notice>
              )}
              {a.status === "failed" && (
                <Notice kind="warn">The run failed before completing. See the agent runs below for the reason.</Notice>
              )}
              {control.error && <ErrorBox message={control.error} />}
            </Section>
            <Section title="Agent runs and failures">
              <AgentRuns assessment={a} />
            </Section>
          </>
        )}
      </Async>
      <Section
        title="Findings"
        actions={<Link to={`/findings?assessment=${id}`}>Open in findings view</Link>}
      >
        <Async state={findings}>
          {(list) =>
            list.length === 0 ? (
              <p className="empty">No findings in this assessment.</p>
            ) : (
              <FindingsTable findings={list} />
            )
          }
        </Async>
      </Section>
      <Section title="Discovered assets">
        <Async state={assets} empty={(l) => l.length === 0}>
          {(list) => (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Asset</th>
                    <th>Scope state</th>
                    <th>Exposure</th>
                    <th>Criticality</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((x) => (
                    <tr key={x.id}>
                      <td>{x.asset_type}</td>
                      <td className="mono">{x.canonical_key}</td>
                      <td>{x.scope_state}</td>
                      <td>{x.exposure ?? "—"}</td>
                      <td>{x.criticality ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Async>
      </Section>
      <Section title="Attack paths">
        <Async state={paths}>
          {(list) =>
            list.length === 0 ? (
              <p className="empty">
                No attack paths were derived. This does not mean the target is safe — it only means no curated
                rule connected the observed findings.
              </p>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Hops</th>
                      <th>Evidence level</th>
                      <th>Path risk</th>
                      <th>Rules</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((p) => (
                      <tr key={p.id}>
                        <td>{p.edge_ids.length}</td>
                        <td>
                          <Badge value={p.evidence_level} />
                        </td>
                        <td>{p.path_risk === null ? "—" : p.path_risk.toFixed(1)}</td>
                        <td>{p.rules_version ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Async>
      </Section>
      <Section title="Reports">
        <ReportsPanel assessmentId={id} canGenerate={can.write} />
      </Section>
    </>
  );
}
