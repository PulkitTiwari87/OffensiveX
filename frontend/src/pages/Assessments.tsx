import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type Assessment } from "../api";
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
  Progress,
  SearchInput,
  Tabs,
  badgeSpec,
  fmtDate,
  useAction,
  useAsync,
  useToast,
} from "../ui";
import { FindingsTable } from "./Findings";

const STATUSES = ["pending", "running", "completed", "completed_with_errors", "failed", "cancelled"];

export function AssessmentsPage() {
  const [status, setStatus] = useState("");
  const [query, setQuery] = useState("");
  const list = useAsync(() => api.assessments({ status: status || undefined, limit: 100 }), [status]);
  const needle = query.trim().toLowerCase();
  const visible = (list.data ?? []).filter((a) => !needle || a.target_name.toLowerCase().includes(needle));

  return (
    <>
      <PageHeader title="Assessments" sub="Runs of the agent pipeline against an authorized target scope." />
      <div className="toolbar" role="group" aria-label="Filter assessments">
        <SearchInput value={query} onChange={setQuery} label="Search assessments" placeholder="Search by target name" />
        <label>
          Status
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">all</option>
            {STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        </label>
        {list.data && (
          <span className="result-count" aria-live="polite">
            {visible.length} of {list.data.length} shown
          </span>
        )}
      </div>
      <Panel flush>
        <Async state={list}>
          {(items) =>
            items.length === 0 ? (
              <EmptyState title={`No assessments${status ? " with this status" : " yet"}.`}>
                Open a target to create one once its scope is approved.
              </EmptyState>
            ) : visible.length === 0 ? (
              <EmptyState title="No assessments match your search." />
            ) : (
              <div className="table-wrap">
                <table className="stack">
                  <thead>
                    <tr>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Mode</th>
                      <th>Started</th>
                      <th>Finished</th>
                      <th className="num">Findings</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((a) => (
                      <tr key={a.id}>
                        <td className="title-cell" data-label="Target">
                          <Link to={`/assessments/${a.id}`}>{a.target_name}</Link>
                        </td>
                        <td data-label="Status">
                          <Badge value={a.status} />
                        </td>
                        <td data-label="Mode">
                          {a.scan_mode}
                          {a.validation_enabled ? " + validation" : ""}
                        </td>
                        <td data-label="Started">{fmtDate(a.started_at)}</td>
                        <td data-label="Finished">{fmtDate(a.finished_at)}</td>
                        <td className="num" data-label="Findings">
                          {a.finding_count}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Async>
      </Panel>
    </>
  );
}

function AgentRuns({ assessment }: { assessment: Assessment }) {
  const runs = [...assessment.agent_runs].sort((a, b) => (a.created_at ?? "").localeCompare(b.created_at ?? ""));
  const failures = runs.filter((r) => r.status === "failed");
  const finished = runs.filter((r) => r.status === "succeeded").length;
  return (
    <>
      {runs.length > 0 && (
        <div className="panel-body">
          <div className="spread small">
            <span>
              {finished} of {runs.length} agent runs succeeded
            </span>
            {failures.length > 0 && <span className="muted">{failures.length} failed</span>}
          </div>
          <Progress
            value={finished}
            max={runs.length}
            label="Agent runs succeeded"
            tone={failures.length > 0 ? "failed" : finished === runs.length ? "done" : undefined}
          />
        </div>
      )}
      {failures.length > 0 && (
        <div className="panel-body">
          <Notice kind="warn">
            {failures.length} agent run{failures.length > 1 ? "s" : ""} failed. The reason is shown on each failed row.
          </Notice>
        </div>
      )}
      {runs.length === 0 ? (
        <EmptyState title="No agent has run yet." />
      ) : (
        <ol className="steps">
          {runs.map((r) => {
            const spec = badgeSpec(r.status);
            return (
              <li key={r.id} className={`step${r.status === "failed" ? " failed" : ""}`}>
                <span className={`tone-${spec.tone}`} style={{ color: "var(--tone)" }}>
                  <Icon name={spec.icon} />
                </span>
                <div>
                  <div className="step-title">{r.agent_type.replace(/_/g, " ")}</div>
                  <div className="muted small">
                    {r.attempts} attempt{r.attempts === 1 ? "" : "s"} · started {fmtDate(r.started_at)} · finished{" "}
                    {fmtDate(r.finished_at)}
                  </div>
                  {r.error && <div className="step-error">{r.error}</div>}
                </div>
                <Badge value={r.status} />
              </li>
            );
          })}
        </ol>
      )}
    </>
  );
}

function ReportsPanel({ assessmentId, canGenerate }: { assessmentId: string; canGenerate: boolean }) {
  const reports = useAsync(() => api.reports(assessmentId), [assessmentId]);
  const action = useAction();
  const toast = useToast();

  async function generate() {
    const created = await action.run(() => api.generateReport(assessmentId, ["json", "markdown"]));
    if (created) {
      toast("ok", "Report generated.");
      reports.reload();
    }
  }

  return (
    <div className="stack-gap">
      {canGenerate && (
        <div>
          <button onClick={generate} disabled={action.busy}>
            {action.busy ? "Generating…" : "Generate report (JSON + Markdown)"}
          </button>
        </div>
      )}
      {action.error && <ErrorBox message={action.error} />}
      <Async
        state={reports}
        empty={(r) => r.length === 0}
        emptyContent={
          <p className="muted">No report has been generated for this assessment yet.</p>
        }
      >
        {(list) => (
          <ul className="legend" style={{ marginTop: 0 }}>
            {list.map((r) => (
              <li key={r.id}>
                <Link to={`/reports/${r.id}`}>{fmtDate(r.generated_at)}</Link>
                <span className="muted small">{r.formats.join(", ")}</span>
              </li>
            ))}
          </ul>
        )}
      </Async>
    </div>
  );
}

type DetailTab = "findings" | "assets" | "paths" | "reports";

export function AssessmentDetailPage() {
  const { id = "" } = useParams();
  const { user } = useAuth();
  const can = capabilities(user?.role);
  const assessment = useAsync(() => api.assessment(id), [id]);
  const findings = useAsync(() => api.findings({ assessment_id: id }), [id]);
  const assets = useAsync(() => api.assets(id), [id]);
  const paths = useAsync(() => api.attackPaths(id), [id]);
  const control = useAction();
  const toast = useToast();
  const [tab, setTab] = useState<DetailTab>("findings");
  const [confirm, setConfirm] = useState<"start" | "cancel" | null>(null);

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

  async function decide(kind: "start" | "cancel") {
    const done = await control.run(() => (kind === "start" ? api.runAssessment(id) : api.cancelAssessment(id)));
    setConfirm(null);
    if (done) {
      toast("ok", kind === "start" ? "Assessment started." : "Assessment cancelled.");
      assessment.reload();
    }
  }

  return (
    <Async state={assessment}>
      {(a) => (
        <>
          <PageHeader
            title="Assessment"
            badge={<Badge value={a.status} />}
            sub={
              <>
                {a.scan_mode} scan{a.validation_enabled ? " with validation" : ""} ·{" "}
                <Link to={`/targets/${a.target_id}`}>open target</Link>
              </>
            }
            actions={
              can.write && notStarted ? (
                <>
                  <button onClick={() => setConfirm("start")} disabled={control.busy}>
                    Start run
                  </button>
                  <button className="danger" onClick={() => setConfirm("cancel")} disabled={control.busy}>
                    Cancel
                  </button>
                </>
              ) : undefined
            }
          />
          {notStarted && (
            <Notice kind="info">Created but not started. Starting it runs the agents against the authorized scope.</Notice>
          )}
          {a.status === "running" && !notStarted && (
            <Notice kind="info">Running — this page refreshes every few seconds.</Notice>
          )}
          {a.status === "failed" && (
            <Notice kind="warn">The run failed before completing. See the agent runs below for the reason.</Notice>
          )}
          {control.error && <ErrorBox message={control.error} />}
          <div className="cols-2-1">
            <Panel title="Agent runs and failures" flush>
              <AgentRuns assessment={a} />
            </Panel>
            <Panel title="Details">
              <dl className="facts">
                <dt>Status</dt>
                <dd>
                  <Badge value={a.status} />
                </dd>
                <dt>Mode</dt>
                <dd>
                  {a.scan_mode}
                  {a.validation_enabled ? " + validation" : ""}
                </dd>
                <dt>Started</dt>
                <dd>{fmtDate(a.started_at)}</dd>
                <dt>Finished</dt>
                <dd>{fmtDate(a.finished_at)}</dd>
              </dl>
            </Panel>
          </div>
          {confirm && (
            <ConfirmDialog
              title={confirm === "start" ? "Start this assessment?" : "Cancel this assessment?"}
              confirmLabel={confirm === "start" ? "Start run" : "Cancel assessment"}
              danger={confirm === "cancel"}
              busy={control.busy}
              onConfirm={() => void decide(confirm)}
              onCancel={() => setConfirm(null)}
            >
              {confirm === "start"
                ? "The agents will run tools against the target's approved scope. Scope enforcement applies to every call."
                : "The assessment will not run. This cannot be undone."}
            </ConfirmDialog>
          )}
          <div className="panel">
            <Tabs
              label="Assessment results"
              value={tab}
              onChange={setTab}
              tabs={[
                { id: "findings", label: "Findings", count: findings.data?.length },
                { id: "assets", label: "Assets", count: assets.data?.length },
                { id: "paths", label: "Attack paths", count: paths.data?.length },
                { id: "reports", label: "Reports" },
              ]}
            />
            <div role="tabpanel" id="panel-findings" aria-labelledby="tab-findings" hidden={tab !== "findings"}>
              <div className="spread panel-body">
                <span className="muted small">Findings recorded by this assessment.</span>
                <Link to={`/findings?assessment=${id}`} className="small">
                  Open in findings view
                </Link>
              </div>
              <Async state={findings}>
                {(list) =>
                  list.length === 0 ? (
                    <EmptyState title="No findings in this assessment." />
                  ) : (
                    <FindingsTable findings={list} />
                  )
                }
              </Async>
            </div>
            <div role="tabpanel" id="panel-assets" aria-labelledby="tab-assets" hidden={tab !== "assets"}>
              <Async state={assets} empty={(l) => l.length === 0} emptyContent={<EmptyState title="No assets discovered yet." />}>
                {(list) => (
                  <div className="table-wrap">
                    <table className="stack">
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
                            <td data-label="Type">{x.asset_type}</td>
                            <td className="mono" data-label="Asset">
                              {x.canonical_key}
                            </td>
                            <td data-label="Scope state">{x.scope_state}</td>
                            <td data-label="Exposure">{x.exposure ? <Badge value={x.exposure} /> : "—"}</td>
                            <td data-label="Criticality">{x.criticality ? <Badge value={x.criticality} /> : "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Async>
            </div>
            <div role="tabpanel" id="panel-paths" aria-labelledby="tab-paths" hidden={tab !== "paths"}>
              <Async state={paths}>
                {(list) =>
                  list.length === 0 ? (
                    <EmptyState title="No attack paths were derived.">
                      This does not mean the target is safe — it only means no curated rule connected the observed
                      findings.
                    </EmptyState>
                  ) : (
                    <>
                      <div className="table-wrap">
                        <table className="stack">
                          <thead>
                            <tr>
                              <th className="num">Hops</th>
                              <th>Evidence level</th>
                              <th className="num">Path risk</th>
                              <th>Rules</th>
                            </tr>
                          </thead>
                          <tbody>
                            {list.map((p) => (
                              <tr key={p.id}>
                                <td className="num" data-label="Hops">
                                  {p.edge_ids.length}
                                </td>
                                <td data-label="Evidence level">
                                  <Badge value={p.evidence_level} />
                                </td>
                                <td className="num" data-label="Path risk">
                                  {p.path_risk === null ? "—" : p.path_risk.toFixed(1)}
                                </td>
                                <td data-label="Rules">{p.rules_version ?? "—"}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <p className="faint small panel-body">
                        A path's evidence level is its weakest link. Inferred and potential paths are not confirmed
                        compromise.
                      </p>
                    </>
                  )
                }
              </Async>
            </div>
            <div role="tabpanel" id="panel-reports" aria-labelledby="tab-reports" hidden={tab !== "reports"}>
              <div className="panel-body">
                <ReportsPanel assessmentId={id} canGenerate={can.write} />
              </div>
            </div>
          </div>
        </>
      )}
    </Async>
  );
}
