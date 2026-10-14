// Thin client for the OffensiveX API. Authentication is the server's HttpOnly,
// SameSite=Strict session cookie (the browser attaches it; this code never sees
// it). The CSRF token is kept in memory only — never in localStorage/sessionStorage —
// and is re-fetched from /auth/me after a page reload.

export type Role = "viewer" | "analyst" | "admin";

export interface User {
  id: string;
  username: string;
  role: Role;
}
export interface Session {
  user: User;
  csrf_token: string;
  expires_at: string;
}
export interface SystemStatus {
  environment: string;
  llm: { enabled: boolean; provider: string | null; model: string | null };
  allow_private_targets: boolean;
  allow_self_approval: boolean;
  session_ttl_minutes: number;
}
export interface RecentAssessment {
  id: string;
  target_id: string;
  target_name: string;
  status: AssessmentStatus;
  started_at: string | null;
  finished_at: string | null;
  finding_count: number;
}
export interface Overview {
  targets: number;
  assessments_by_status: Record<string, number>;
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
  recent_assessments: RecentAssessment[];
}
export type Impact = "low" | "medium" | "high" | "critical";
export interface Target {
  id: string;
  name: string;
  type: string;
  entry_point: string | null;
  default_exposure: Impact;
  default_criticality: Impact;
}
export interface ScopeRule {
  rule_type: string;
  pattern: string;
  is_exclusion: boolean;
  ports: string | null;
}
export type AuthorizationStatus = "pending" | "approved" | "rejected" | "revoked" | "expired";
export interface Authorization {
  id: string;
  target_id: string;
  version: number;
  status: AuthorizationStatus;
  valid_from: string;
  valid_until: string;
  attestation: string | null;
  submitted_by_id: string | null;
  decided_by_id: string | null;
  scope_rules: ScopeRule[];
}
export type AssessmentStatus =
  | "pending"
  | "running"
  | "completed"
  | "completed_with_errors"
  | "failed"
  | "cancelled";
export interface AgentRun {
  id: string;
  agent_type: string;
  status: string;
  attempts: number;
  error: string | null;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
}
export interface Assessment {
  id: string;
  target_id: string;
  authorization_id: string;
  scan_mode: string;
  validation_enabled: boolean;
  status: AssessmentStatus;
  started_at: string | null;
  finished_at: string | null;
  agent_runs: AgentRun[];
}
export interface AssessmentListItem {
  id: string;
  target_id: string;
  target_name: string;
  status: AssessmentStatus;
  scan_mode: string;
  validation_enabled: boolean;
  started_at: string | null;
  finished_at: string | null;
  finding_count: number;
}
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export interface Finding {
  id: string;
  assessment_id: string;
  asset_id: string;
  asset_identifier: string;
  title: string;
  severity: Severity;
  confidence: number;
  source: string;
  affected_component: string | null;
  status: string;
  risk_score: number | null;
  first_seen: string;
  last_seen: string;
}
export interface Evidence {
  id: string;
  kind: string;
  tool_execution_id: string;
  excerpt: string;
  captured_at: string;
}
export interface FindingDetail extends Finding {
  description: string | null;
  risk_breakdown: Record<string, unknown> | null;
  evidence: Evidence[];
}
export interface Asset {
  id: string;
  asset_type: string;
  canonical_key: string;
  attributes: Record<string, unknown>;
  criticality: Impact | null;
  exposure: Impact | null;
  scope_state: string;
}
export interface AttackPath {
  id: string;
  entry_node_id: string;
  target_node_id: string;
  edge_ids: unknown[];
  path_risk: number | null;
  evidence_level: string;
  rules_version: string | null;
}
export interface Report {
  id: string;
  assessment_id: string;
  formats: string[];
  provenance: Record<string, unknown>;
  content_json: Record<string, unknown> | null;
  content_markdown: string | null;
  generated_at: string;
}
export interface AuditEntry {
  id: string;
  occurred_at: string;
  actor_username: string | null;
  action: string;
  outcome: string;
  target_type: string | null;
  target_id: string | null;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

function describeError(data: unknown, fallback: string): string {
  if (data && typeof data === "object") {
    const body = data as { detail?: unknown; errors?: unknown; title?: unknown };
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.errors)) {
      return body.errors
        .map((e: { loc?: unknown[]; msg?: string }) =>
          `${(e.loc ?? []).slice(1).join(".")}: ${e.msg ?? "invalid"}`.replace(/^: /, ""),
        )
        .join("; ");
    }
    if (typeof body.title === "string") return body.title;
  }
  return fallback;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  opts: { auth?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "Cannot reach the API. Is the backend running?");
  }
  if (response.status === 204) return undefined as T;
  const data: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && opts.auth !== false) onUnauthorized?.();
    throw new ApiError(
      response.status,
      describeError(data, `Request failed (HTTP ${response.status})`),
    );
  }
  return data as T;
}

const get = <T>(path: string) => request<T>("GET", path);
const post = <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {});
const qs = (params: Record<string, string | number | undefined>): string => {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== "");
  return entries.length
    ? "?" + new URLSearchParams(entries.map(([k, v]) => [k, String(v)])).toString()
    : "";
};

export const api = {
  login: async (username: string, password: string): Promise<Session> => {
    const session = await request<Session>("POST", "/auth/login", { username, password }, { auth: false });
    csrfToken = session.csrf_token;
    return session;
  },
  me: async (): Promise<Session> => {
    const session = await request<Session>("GET", "/auth/me", undefined, { auth: false });
    csrfToken = session.csrf_token;
    return session;
  },
  logout: async (): Promise<void> => {
    await request<void>("POST", "/auth/logout", {}, { auth: false });
    csrfToken = null;
  },
  systemStatus: () => get<SystemStatus>("/system/status"),
  overview: () => get<Overview>("/overview"),

  targets: () => get<Target[]>("/targets"),
  target: (id: string) => get<Target>(`/targets/${id}`),
  createTarget: (body: {
    name: string;
    type: string;
    entry_point?: string;
    default_exposure: Impact;
    default_criticality: Impact;
  }) => post<Target>("/targets", body),
  authorizations: (targetId: string) => get<Authorization[]>(`/targets/${targetId}/authorizations`),
  submitAuthorization: (
    targetId: string,
    body: { scope_rules: ScopeRule[]; attestation: string; valid_from: string; valid_until: string },
  ) => post<Authorization>(`/targets/${targetId}/authorizations`, body),
  decideAuthorization: (targetId: string, version: number, decision: "approve" | "reject") =>
    post<Authorization>(`/targets/${targetId}/authorizations/${version}/${decision}`),

  assessments: (params: { status?: string; target_id?: string; limit?: number } = {}) =>
    get<AssessmentListItem[]>(`/assessments${qs(params)}`),
  assessment: (id: string) => get<Assessment>(`/assessments/${id}`),
  createAssessment: (body: { target_id: string; scan_mode: string; validation_enabled: boolean }) =>
    post<Assessment>("/assessments", body),
  runAssessment: (id: string) => post<Assessment>(`/assessments/${id}/run`),
  cancelAssessment: (id: string) => post<Assessment>(`/assessments/${id}/cancel`),
  assets: (id: string) => get<Asset[]>(`/assessments/${id}/assets`),
  attackPaths: (id: string) => get<AttackPath[]>(`/assessments/${id}/attack-paths`),

  findings: (params: { assessment_id?: string; status?: string; severity?: string } = {}) =>
    get<Finding[]>(`/findings${qs(params)}`),
  finding: (id: string) => get<FindingDetail>(`/findings/${id}`),
  overrideFinding: (id: string, status: "confirmed" | "rejected", reason: string) =>
    request<FindingDetail>("PATCH", `/findings/${id}/status`, { status, reason: reason || null }),

  reports: (assessmentId: string) => get<Report[]>(`/assessments/${assessmentId}/reports`),
  generateReport: (assessmentId: string, formats: string[]) =>
    post<Report>(`/assessments/${assessmentId}/reports`, { formats }),
  report: (id: string) => get<Report>(`/reports/${id}`),

  audit: (params: { action?: string; limit?: number } = {}) =>
    get<AuditEntry[]>(`/audit-log${qs(params)}`),
};
