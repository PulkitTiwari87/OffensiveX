import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Authorization, type Impact, type ScopeRule } from "../api";
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
  SearchInput,
  fmtDate,
  useAction,
  useAsync,
  useToast,
} from "../ui";

const LEVELS: Impact[] = ["low", "medium", "high", "critical"];

function CreateTargetForm({ onCreated }: { onCreated: (id: string) => void }) {
  const [name, setName] = useState("");
  const [type, setType] = useState("web_application");
  const [entry, setEntry] = useState("");
  const [exposure, setExposure] = useState<Impact>("medium");
  const [criticality, setCriticality] = useState<Impact>("medium");
  const action = useAction();

  async function submit(e: FormEvent) {
    e.preventDefault();
    const created = await action.run(() =>
      api.createTarget({
        name: name.trim(),
        type: type.trim(),
        entry_point: entry.trim() || undefined,
        default_exposure: exposure,
        default_criticality: criticality,
      }),
    );
    if (created) onCreated(created.id);
  }

  return (
    <form onSubmit={submit} className="form" aria-label="Create target">
      <label>
        Name
        <input value={name} onChange={(e) => setName(e.target.value)} required />
      </label>
      <label>
        Type
        <input value={type} onChange={(e) => setType(e.target.value)} required />
      </label>
      <label>
        Entry point
        <input
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
          placeholder="http://localhost:8080/"
          inputMode="url"
        />
        <span className="field-hint">Optional http/https URL. It must fall inside the scope you submit later.</span>
      </label>
      <label>
        Exposure
        <select value={exposure} onChange={(e) => setExposure(e.target.value as Impact)}>
          {LEVELS.map((l) => (
            <option key={l}>{l}</option>
          ))}
        </select>
      </label>
      <label>
        Criticality
        <select value={criticality} onChange={(e) => setCriticality(e.target.value as Impact)}>
          {LEVELS.map((l) => (
            <option key={l}>{l}</option>
          ))}
        </select>
      </label>
      {action.error && <ErrorBox message={action.error} />}
      <div>
        <button type="submit" disabled={action.busy}>
          {action.busy ? "Creating…" : "Create target"}
        </button>
      </div>
    </form>
  );
}

export function TargetsPage() {
  const { user } = useAuth();
  const can = capabilities(user?.role);
  const targets = useAsync(api.targets, []);
  const navigate = useNavigate();
  const toast = useToast();
  const [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const visible = (targets.data ?? []).filter(
    (t) => !needle || [t.name, t.type, t.entry_point ?? ""].some((s) => s.toLowerCase().includes(needle)),
  );

  return (
    <>
      <PageHeader title="Targets" sub="Systems you are authorized to assess. Nothing runs without an approved scope." />
      <div className="cols-2-1">
        <div>
          <div className="toolbar">
            <SearchInput value={query} onChange={setQuery} label="Search targets" placeholder="Search name, type, entry point" />
            {targets.data && (
              <span className="result-count" aria-live="polite">
                {visible.length} of {targets.data.length} shown
              </span>
            )}
          </div>
          <Panel flush>
            <Async
              state={targets}
              empty={(t) => t.length === 0}
              emptyContent={
                <EmptyState title="No targets yet.">
                  {can.write ? "Create one with the form to get started." : "An analyst or administrator can add targets."}
                </EmptyState>
              }
            >
              {() =>
                visible.length === 0 ? (
                  <EmptyState title="No targets match your search." />
                ) : (
                  <div className="table-wrap">
                    <table className="stack">
                      <thead>
                        <tr>
                          <th>Name</th>
                          <th>Type</th>
                          <th>Entry point</th>
                          <th>Exposure</th>
                          <th>Criticality</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visible.map((t) => (
                          <tr key={t.id}>
                            <td className="title-cell" data-label="Name">
                              <Link to={`/targets/${t.id}`}>{t.name}</Link>
                            </td>
                            <td data-label="Type">{t.type}</td>
                            <td className="mono" data-label="Entry point">
                              {t.entry_point ?? "—"}
                            </td>
                            <td data-label="Exposure">
                              <Badge value={t.default_exposure} />
                            </td>
                            <td data-label="Criticality">
                              <Badge value={t.default_criticality} />
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
        </div>
        <div>
          {can.write ? (
            <Panel title="Create target">
              <CreateTargetForm
                onCreated={(id) => {
                  toast("ok", "Target created. Submit its scope for approval next.");
                  navigate(`/targets/${id}`);
                }}
              />
            </Panel>
          ) : (
            <Notice kind="info">Your role is read-only; creating targets needs the analyst or admin role.</Notice>
          )}
        </div>
      </div>
    </>
  );
}

function describePorts(rule: ScopeRule): string {
  if (rule.ports) return rule.ports;
  return rule.is_exclusion ? "all ports" : "80, 443 (default)";
}

function ScopeEffect({ exclude }: { exclude: boolean }) {
  return exclude ? (
    <span className="badge tone-critical">
      <Icon name="minus" size={12} />
      exclude
    </span>
  ) : (
    <span className="badge tone-ok">
      <Icon name="check" size={12} />
      include
    </span>
  );
}

function ScopeTable({ rules }: { rules: ScopeRule[] }) {
  return (
    <div className="table-wrap">
      <table className="stack">
        <thead>
          <tr>
            <th>Effect</th>
            <th>Type</th>
            <th>Host / network</th>
            <th>Ports</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r, i) => (
            <tr key={i}>
              <td data-label="Effect">
                <ScopeEffect exclude={r.is_exclusion} />
              </td>
              <td data-label="Type">{r.rule_type}</td>
              <td className="mono" data-label="Host / network">
                {r.pattern}
              </td>
              <td className="mono" data-label="Ports">
                {describePorts(r)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AuthorizationCard({
  auth,
  canDecide,
  onDecided,
}: {
  auth: Authorization;
  canDecide: boolean;
  onDecided: () => void;
}) {
  const action = useAction();
  const toast = useToast();
  const [pending, setPending] = useState<"approve" | "reject" | null>(null);

  async function decide(decision: "approve" | "reject") {
    const done = await action.run(() => api.decideAuthorization(auth.target_id, auth.version, decision));
    setPending(null);
    if (done) {
      toast("ok", `Scope version ${auth.version} ${decision === "approve" ? "approved" : "rejected"}.`);
      onDecided();
    }
  }

  return (
    <Panel nested flush>
      <div className="panel-head">
        <div className="row">
          <strong>Version {auth.version}</strong>
          <Badge value={auth.status} />
        </div>
        <span className="muted small">
          valid {fmtDate(auth.valid_from)} → {fmtDate(auth.valid_until)}
        </span>
      </div>
      {auth.attestation && (
        <div className="panel-body">
          <span className="faint small">Attestation</span>
          <p className="muted" style={{ margin: 0 }}>
            {auth.attestation}
          </p>
        </div>
      )}
      <ScopeTable rules={auth.scope_rules} />
      {auth.status === "pending" && (
        <div className="panel-body">
          {canDecide ? (
            <div className="row">
              <button disabled={action.busy} onClick={() => setPending("approve")}>
                Approve
              </button>
              <button className="danger" disabled={action.busy} onClick={() => setPending("reject")}>
                Reject
              </button>
            </div>
          ) : (
            <p className="muted small" style={{ margin: 0 }}>
              Waiting for an administrator to approve this scope.
            </p>
          )}
        </div>
      )}
      {action.error && (
        <div className="panel-body">
          <ErrorBox message={action.error} />
        </div>
      )}
      {pending && (
        <ConfirmDialog
          title={pending === "approve" ? `Approve scope version ${auth.version}?` : `Reject scope version ${auth.version}?`}
          confirmLabel={pending === "approve" ? "Approve scope" : "Reject scope"}
          danger={pending === "reject"}
          busy={action.busy}
          onConfirm={() => void decide(pending)}
          onCancel={() => setPending(null)}
        >
          {pending === "approve"
            ? "Approving authorizes assessments against exactly the included hosts and ports above, for the validity window shown. The decision is recorded in the audit log."
            : "This scope will not be usable for assessments. The decision is recorded in the audit log."}
        </ConfirmDialog>
      )}
    </Panel>
  );
}

interface RuleRow {
  rule_type: string;
  pattern: string;
  ports: string;
  is_exclusion: boolean;
}

function SubmitAuthorizationForm({ targetId, onSubmitted }: { targetId: string; onSubmitted: () => void }) {
  const [rows, setRows] = useState<RuleRow[]>([{ rule_type: "domain", pattern: "", ports: "", is_exclusion: false }]);
  const [attestation, setAttestation] = useState("");
  const [days, setDays] = useState(7);
  const action = useAction();
  const toast = useToast();

  const update = (i: number, patch: Partial<RuleRow>) =>
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  async function submit(e: FormEvent) {
    e.preventDefault();
    const now = new Date();
    const until = new Date(now.getTime() + days * 86_400_000);
    const done = await action.run(() =>
      api.submitAuthorization(targetId, {
        scope_rules: rows.map((r) => ({
          rule_type: r.rule_type,
          pattern: r.pattern.trim(),
          is_exclusion: r.is_exclusion,
          ports: r.ports.trim() || null,
        })),
        attestation: attestation.trim(),
        valid_from: now.toISOString(),
        valid_until: until.toISOString(),
      }),
    );
    if (done) {
      toast("ok", "Scope submitted for approval.");
      onSubmitted();
    }
  }

  return (
    <form onSubmit={submit} className="form" aria-label="Submit authorization">
      {rows.map((r, i) => (
        <div className="rule-row" key={i}>
          <select
            aria-label={`Rule ${i + 1} type`}
            value={r.rule_type}
            onChange={(e) => update(i, { rule_type: e.target.value })}
          >
            <option>domain</option>
            <option>cidr</option>
          </select>
          <input
            aria-label={`Rule ${i + 1} host or network`}
            placeholder="localhost or 10.0.0.0/24"
            value={r.pattern}
            onChange={(e) => update(i, { pattern: e.target.value })}
            required
          />
          <input
            aria-label={`Rule ${i + 1} ports`}
            placeholder={r.is_exclusion ? "ports (blank = all)" : "ports e.g. 8000-8100 (blank = 80,443)"}
            value={r.ports}
            onChange={(e) => update(i, { ports: e.target.value })}
          />
          <label className="inline">
            <input
              type="checkbox"
              checked={r.is_exclusion}
              onChange={(e) => update(i, { is_exclusion: e.target.checked })}
            />
            exclude
          </label>
          {rows.length > 1 && (
            <button type="button" className="secondary" onClick={() => setRows(rows.filter((_, j) => j !== i))}>
              Remove
            </button>
          )}
        </div>
      ))}
      <div>
        <button
          type="button"
          className="secondary"
          onClick={() => setRows([...rows, { rule_type: "domain", pattern: "", ports: "", is_exclusion: false }])}
        >
          Add rule
        </button>
      </div>
      <label>
        Attestation (you are authorized to assess this target)
        <textarea value={attestation} onChange={(e) => setAttestation(e.target.value)} required />
      </label>
      <label>
        Valid for (days)
        <input type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} />
      </label>
      {action.error && <ErrorBox message={action.error} />}
      <div>
        <button type="submit" disabled={action.busy}>
          {action.busy ? "Submitting…" : "Submit for approval"}
        </button>
      </div>
    </form>
  );
}

function NewAssessment({ targetId, hasApproved }: { targetId: string; hasApproved: boolean }) {
  const [mode, setMode] = useState("standard");
  const [validate, setValidate] = useState(false);
  const action = useAction();
  const navigate = useNavigate();
  const toast = useToast();

  async function create() {
    const created = await action.run(() =>
      api.createAssessment({ target_id: targetId, scan_mode: mode, validation_enabled: validate }),
    );
    if (created) {
      toast("ok", "Assessment created. Review it, then start the run.");
      navigate(`/assessments/${created.id}`);
    }
  }

  return (
    <div className="form">
      {!hasApproved && (
        <Notice kind="warn">No approved authorization is on record, so the server will refuse a new assessment.</Notice>
      )}
      <label>
        Scan mode
        <select value={mode} onChange={(e) => setMode(e.target.value)}>
          <option>quick</option>
          <option>standard</option>
          <option>deep</option>
        </select>
      </label>
      <label className="inline">
        <input type="checkbox" checked={validate} onChange={(e) => setValidate(e.target.checked)} />
        Enable the Validation Agent (runs additional non-destructive checks)
      </label>
      {action.error && <ErrorBox message={action.error} />}
      <div>
        <button onClick={create} disabled={action.busy}>
          {action.busy ? "Creating…" : "Create assessment"}
        </button>
      </div>
    </div>
  );
}

export function TargetDetailPage() {
  const { id = "" } = useParams();
  const { user } = useAuth();
  const can = capabilities(user?.role);
  const target = useAsync(() => api.target(id), [id]);
  const auths = useAsync(() => api.authorizations(id), [id]);
  const assessments = useAsync(() => api.assessments({ target_id: id }), [id]);

  return (
    <>
      <Async state={target}>
        {(t) => (
          <PageHeader title={t.name} sub={<span className="mono">{t.entry_point ?? "No entry point set"}</span>} />
        )}
      </Async>
      <div className="cols-2-1">
        <div>
          <Panel title="Authorizations and scope">
            <Async
              state={auths}
              empty={(a) => a.length === 0}
              emptyContent={
                <Notice kind="warn">
                  No scope has been submitted. Nothing can be assessed until an administrator approves one.
                </Notice>
              }
            >
              {(list) => (
                <>
                  {!list.some((a) => a.status === "approved") && (
                    <Notice kind="warn">No approved scope is active, so assessments are blocked for this target.</Notice>
                  )}
                  {list.map((a) => (
                    <AuthorizationCard key={a.id} auth={a} canDecide={can.decide} onDecided={auths.reload} />
                  ))}
                </>
              )}
            </Async>
          </Panel>
          {can.write && (
            <Panel title="Submit a new authorization">
              <SubmitAuthorizationForm targetId={id} onSubmitted={auths.reload} />
            </Panel>
          )}
        </div>
        <div>
          <Async state={target}>
            {(t) => (
              <Panel title="Details">
                <dl className="facts">
                  <dt>Type</dt>
                  <dd>{t.type}</dd>
                  <dt>Exposure</dt>
                  <dd>
                    <Badge value={t.default_exposure} />
                  </dd>
                  <dt>Criticality</dt>
                  <dd>
                    <Badge value={t.default_criticality} />
                  </dd>
                </dl>
              </Panel>
            )}
          </Async>
          {can.write && (
            <Panel title="Create assessment">
              <NewAssessment targetId={id} hasApproved={(auths.data ?? []).some((a) => a.status === "approved")} />
            </Panel>
          )}
        </div>
      </div>
      <Panel title="Assessments of this target" flush>
        <Async
          state={assessments}
          empty={(a) => a.length === 0}
          emptyContent={<EmptyState title="No assessments of this target yet." />}
        >
          {(list) => (
            <div className="table-wrap">
              <table className="stack">
                <thead>
                  <tr>
                    <th>Started</th>
                    <th>Status</th>
                    <th>Mode</th>
                    <th className="num">Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {list.map((a) => (
                    <tr key={a.id}>
                      <td className="title-cell" data-label="Started">
                        <Link to={`/assessments/${a.id}`}>{a.started_at ? fmtDate(a.started_at) : "Not started"}</Link>
                      </td>
                      <td data-label="Status">
                        <Badge value={a.status} />
                      </td>
                      <td data-label="Mode">
                        {a.scan_mode}
                        {a.validation_enabled ? " + validation" : ""}
                      </td>
                      <td className="num" data-label="Findings">
                        {a.finding_count}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Async>
      </Panel>
    </>
  );
}
