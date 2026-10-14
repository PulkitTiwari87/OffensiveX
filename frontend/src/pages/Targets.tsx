import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Authorization, type Impact, type ScopeRule } from "../api";
import { capabilities, useAuth } from "../auth";
import { Async, Badge, ErrorBox, Notice, Section, fmtDate, useAction, useAsync } from "../ui";

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
        Entry point (http/https URL, optional)
        <input
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
          placeholder="http://localhost:8080/"
        />
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
      <button type="submit" disabled={action.busy}>
        Create target
      </button>
    </form>
  );
}

export function TargetsPage() {
  const { user } = useAuth();
  const can = capabilities(user?.role);
  const targets = useAsync(api.targets, []);
  const navigate = useNavigate();

  return (
    <>
      <h1>Targets</h1>
      <Section title="All targets">
        <Async state={targets} empty={(t) => t.length === 0}>
          {(list) => (
            <div className="table-wrap">
              <table>
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
                  {list.map((t) => (
                    <tr key={t.id}>
                      <td>
                        <Link to={`/targets/${t.id}`}>{t.name}</Link>
                      </td>
                      <td>{t.type}</td>
                      <td>{t.entry_point ?? "—"}</td>
                      <td>{t.default_exposure}</td>
                      <td>{t.default_criticality}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Async>
      </Section>
      {can.write ? (
        <Section title="Create target">
          <CreateTargetForm onCreated={(id) => navigate(`/targets/${id}`)} />
        </Section>
      ) : (
        <Notice kind="info">Your role is read-only; creating targets needs the analyst or admin role.</Notice>
      )}
    </>
  );
}

function describePorts(rule: ScopeRule): string {
  if (rule.ports) return rule.ports;
  return rule.is_exclusion ? "all ports" : "80, 443 (default)";
}

function ScopeTable({ rules }: { rules: ScopeRule[] }) {
  return (
    <div className="table-wrap">
      <table>
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
              <td>{r.is_exclusion ? "exclude" : "include"}</td>
              <td>{r.rule_type}</td>
              <td>{r.pattern}</td>
              <td>{describePorts(r)}</td>
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
  async function decide(decision: "approve" | "reject") {
    const done = await action.run(() => api.decideAuthorization(auth.target_id, auth.version, decision));
    if (done) onDecided();
  }
  return (
    <div className="subcard">
      <p>
        <strong>Version {auth.version}</strong> <Badge value={auth.status} /> · valid{" "}
        {fmtDate(auth.valid_from)} → {fmtDate(auth.valid_until)}
      </p>
      {auth.attestation && <p className="muted">Attestation: {auth.attestation}</p>}
      <ScopeTable rules={auth.scope_rules} />
      {auth.status === "pending" && canDecide && (
        <div className="row">
          <button disabled={action.busy} onClick={() => decide("approve")}>
            Approve
          </button>
          <button className="secondary" disabled={action.busy} onClick={() => decide("reject")}>
            Reject
          </button>
        </div>
      )}
      {auth.status === "pending" && !canDecide && (
        <p className="muted small">Waiting for an administrator to approve this scope.</p>
      )}
      {action.error && <ErrorBox message={action.error} />}
    </div>
  );
}

interface RuleRow {
  rule_type: string;
  pattern: string;
  ports: string;
  is_exclusion: boolean;
}

function SubmitAuthorizationForm({ targetId, onSubmitted }: { targetId: string; onSubmitted: () => void }) {
  const [rows, setRows] = useState<RuleRow[]>([
    { rule_type: "domain", pattern: "", ports: "", is_exclusion: false },
  ]);
  const [attestation, setAttestation] = useState("");
  const [days, setDays] = useState(7);
  const action = useAction();

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
    if (done) onSubmitted();
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
      <button
        type="button"
        className="secondary"
        onClick={() => setRows([...rows, { rule_type: "domain", pattern: "", ports: "", is_exclusion: false }])}
      >
        Add rule
      </button>
      <label>
        Attestation (you are authorized to assess this target)
        <textarea value={attestation} onChange={(e) => setAttestation(e.target.value)} required />
      </label>
      <label>
        Valid for (days)
        <input type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} />
      </label>
      {action.error && <ErrorBox message={action.error} />}
      <button type="submit" disabled={action.busy}>
        Submit for approval
      </button>
    </form>
  );
}

function NewAssessment({ targetId, hasApproved }: { targetId: string; hasApproved: boolean }) {
  const [mode, setMode] = useState("standard");
  const [validate, setValidate] = useState(false);
  const action = useAction();
  const navigate = useNavigate();

  async function create() {
    const created = await action.run(() =>
      api.createAssessment({ target_id: targetId, scan_mode: mode, validation_enabled: validate }),
    );
    if (created) navigate(`/assessments/${created.id}`);
  }

  return (
    <div className="form">
      {!hasApproved && (
        <Notice kind="warn">
          No approved authorization is on record, so the server will refuse a new assessment.
        </Notice>
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
      <button onClick={create} disabled={action.busy}>
        Create assessment
      </button>
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
      <p>
        <Link to="/targets">← Targets</Link>
      </p>
      <Async state={target}>
        {(t) => (
          <>
            <h1>{t.name}</h1>
            <Section title="Details">
              <dl className="facts">
                <dt>Type</dt>
                <dd>{t.type}</dd>
                <dt>Entry point</dt>
                <dd>{t.entry_point ?? "none set"}</dd>
                <dt>Exposure / criticality</dt>
                <dd>
                  {t.default_exposure} / {t.default_criticality}
                </dd>
              </dl>
            </Section>
          </>
        )}
      </Async>
      <Section title="Authorizations and scope">
        <Async state={auths} empty={(a) => a.length === 0}>
          {(list) =>
            list.map((a) => (
              <AuthorizationCard key={a.id} auth={a} canDecide={can.decide} onDecided={auths.reload} />
            ))
          }
        </Async>
        {auths.data?.length === 0 && (
          <p className="muted">No scope has been submitted. Nothing can be assessed until an administrator approves one.</p>
        )}
      </Section>
      {can.write && (
        <>
          <Section title="Submit a new authorization">
            <SubmitAuthorizationForm targetId={id} onSubmitted={auths.reload} />
          </Section>
          <Section title="Create assessment">
            <NewAssessment
              targetId={id}
              hasApproved={(auths.data ?? []).some((a) => a.status === "approved")}
            />
          </Section>
        </>
      )}
      <Section title="Assessments of this target">
        <Async state={assessments} empty={(a) => a.length === 0}>
          {(list) => (
            <ul>
              {list.map((a) => (
                <li key={a.id}>
                  <Link to={`/assessments/${a.id}`}>{fmtDate(a.started_at)}</Link> <Badge value={a.status} /> ·{" "}
                  {a.finding_count} findings
                </li>
              ))}
            </ul>
          )}
        </Async>
      </Section>
    </>
  );
}
