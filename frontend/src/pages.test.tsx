import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { setCsrfToken } from "./api";
import { AuthProvider } from "./auth";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const me = (role: string) => ({
  user: { id: "u1", username: "alice", role },
  csrf_token: "csrf-1",
  expires_at: "2099-01-01T00:00:00Z",
});
const SYSTEM = {
  environment: "development",
  llm: { enabled: false, provider: null, model: null },
  allow_private_targets: false,
  allow_self_approval: false,
  session_ttl_minutes: 480,
};
const EMPTY_OVERVIEW = {
  targets: 0,
  assessments_by_status: {},
  findings_by_severity: {},
  findings_by_status: {},
  recent_assessments: [],
};

type Handler = unknown | ((init: RequestInit) => unknown);

/** Routes a stubbed fetch by "METHOD /path?query" (without the /api/v1 prefix). */
function setupFetch(routes: Record<string, Handler>) {
  const calls: { key: string; init: RequestInit }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit = {}) => {
      const key = `${init.method ?? "GET"} ${url.replace("/api/v1", "")}`;
      calls.push({ key, init });
      const handler = routes[key];
      if (handler === undefined) return json(404, { detail: `unmocked ${key}` });
      const out = typeof handler === "function" ? (handler as (i: RequestInit) => unknown)(init) : handler;
      return out instanceof Response ? out : json(200, out);
    }),
  );
  return calls;
}

function mount(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

const finding = (over: Record<string, unknown>) => ({
  id: "f",
  assessment_id: "a1",
  asset_id: "as",
  asset_identifier: "http://localhost:8080/",
  title: "Missing security header: X",
  severity: "medium",
  confidence: 1,
  source: "security_header_scan",
  affected_component: "X",
  status: "investigating",
  risk_score: null,
  first_seen: "2026-01-01T00:00:00Z",
  last_seen: "2026-01-02T00:00:00Z",
  ...over,
});

beforeEach(() => {
  setCsrfToken(null);
  localStorage.clear();
});

describe("login", () => {
  it("shows the sign-in form when there is no session, and surfaces a bad password", async () => {
    setupFetch({
      "GET /auth/me": json(401, { detail: "Authentication required." }),
      "POST /auth/login": json(401, { detail: "Invalid username or password." }),
    });
    mount("/");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Username"), "alice");
    await user.type(screen.getByLabelText("Password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid username or password.");
    expect(screen.getByLabelText("Password")).toHaveValue(""); // cleared after sending
    expect(localStorage.length).toBe(0);
  });

  it("signs in and then shows the overview with an honest empty state", async () => {
    let authed = false;
    setupFetch({
      "GET /auth/me": () => (authed ? me("analyst") : json(401, { detail: "Authentication required." })),
      "POST /auth/login": () => {
        authed = true;
        return me("analyst");
      },
      "GET /system/status": SYSTEM,
      "GET /overview": EMPTY_OVERVIEW,
    });
    mount("/");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Username"), "alice");
    await user.type(screen.getByLabelText("Password"), "pw");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(await screen.findByText(/No LLM is configured/)).toBeInTheDocument();
    expect(screen.getByText(/Nothing has run yet/)).toBeInTheDocument();
  });
});

describe("navigation and system status", () => {
  it("renders the shell with labelled navigation, breadcrumbs and the signed-in role", async () => {
    setupFetch({ "GET /auth/me": me("analyst"), "GET /system/status": SYSTEM, "GET /overview": EMPTY_OVERVIEW });
    mount("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    for (const name of ["Overview", "Targets", "Assessments", "Findings", "System"]) {
      expect(within(nav).getByRole("link", { name })).toBeInTheDocument();
    }
    expect(within(nav).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent("Overview");
    expect(screen.getByText("analyst")).toBeInTheDocument();
  });

  it("shows an honest 404 for unknown routes", async () => {
    setupFetch({ "GET /auth/me": me("viewer") });
    mount("/nope");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });

  it("shows system status, flags risky switches, and never shows secrets", async () => {
    setupFetch({
      "GET /auth/me": me("viewer"),
      "GET /system/status": {
        ...SYSTEM,
        llm: { enabled: true, provider: "anthropic", model: "claude-test" },
        allow_self_approval: true,
      },
    });
    mount("/system");
    expect(await screen.findByText("claude-test")).toBeInTheDocument();
    expect(screen.getByText(/Self-approval is on/)).toBeInTheDocument();
    expect(screen.getByText("480 minutes")).toBeInTheDocument();
  });

  it("shows an unavailable state, with retry, when the API is unreachable", async () => {
    setupFetch({ "GET /auth/me": me("viewer"), "GET /system/status": json(500, { detail: "boom" }) });
    mount("/system");
    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });
});

describe("role-based controls (display only; the server stays authoritative)", () => {
  const targets = [
    { id: "t1", name: "lab", type: "web", entry_point: "http://localhost:8080/", default_exposure: "medium", default_criticality: "medium" },
  ];

  it("hides the create form from a viewer", async () => {
    setupFetch({ "GET /auth/me": me("viewer"), "GET /targets": targets });
    mount("/targets");
    expect(await screen.findByText("lab")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Create target" })).not.toBeInTheDocument();
    expect(screen.getByText(/read-only/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Audit" })).not.toBeInTheDocument();
  });

  it("shows the form to an analyst but still reports a server-side refusal", async () => {
    setupFetch({
      "GET /auth/me": me("analyst"),
      "GET /targets": targets,
      "POST /targets": json(422, { detail: "Entry point is outside the allowed scope." }),
    });
    mount("/targets");
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Name"), "new-target");
    await user.click(screen.getByRole("button", { name: "Create target" }));
    expect(await screen.findByText("Entry point is outside the allowed scope.")).toBeInTheDocument();
  });

  it("shows the audit link only to an administrator", async () => {
    setupFetch({ "GET /auth/me": me("admin"), "GET /system/status": SYSTEM, "GET /overview": EMPTY_OVERVIEW });
    mount("/");
    expect(await screen.findByRole("link", { name: "Audit" })).toBeInTheDocument();
  });

  it("explains the server's 403 on the audit page instead of showing a blank screen", async () => {
    setupFetch({
      "GET /auth/me": me("admin"),
      "GET /audit-log?limit=200": json(403, { detail: "You do not have permission to perform this action." }),
    });
    mount("/audit");
    expect(await screen.findByRole("alert")).toHaveTextContent("Not allowed: You do not have permission");
  });
});

describe("authorizations", () => {
  const auth = {
    id: "az1",
    target_id: "t1",
    version: 1,
    status: "pending",
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2026-01-08T00:00:00Z",
    attestation: "I own this",
    submitted_by_id: "u2",
    decided_by_id: null,
    scope_rules: [
      { rule_type: "domain", pattern: "localhost", is_exclusion: false, ports: "8080" },
      { rule_type: "domain", pattern: "admin.localhost", is_exclusion: true, ports: null },
    ],
  };
  const routes = (role: string): Record<string, Handler> => ({
    "GET /auth/me": me(role),
    "GET /targets/t1": { id: "t1", name: "lab", type: "web", entry_point: null, default_exposure: "low", default_criticality: "low" },
    "GET /targets/t1/authorizations": [auth],
    "GET /assessments?target_id=t1": [],
  });

  it("shows hosts and ports, lets an admin decide, and sends CSRF with the decision", async () => {
    const calls = setupFetch({
      ...routes("admin"),
      "POST /targets/t1/authorizations/1/approve": { ...auth, status: "approved" },
    });
    mount("/targets/t1");
    const scope = (await screen.findAllByRole("table"))[0];
    expect(within(scope).getByText("8080")).toBeInTheDocument();
    expect(within(scope).getByText("all ports")).toBeInTheDocument(); // exclusion without ports
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Approve" }));
    // Approving grants scan authority, so it asks first and nothing is sent until confirmed.
    expect(calls.some((c) => c.key.endsWith("/approve"))).toBe(false);
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Approve scope" }));
    await waitFor(() => expect(calls.some((c) => c.key.endsWith("/approve"))).toBe(true));
    const approve = calls.find((c) => c.key.endsWith("/approve"))!;
    expect((approve.init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-1");
  });

  it("gives an analyst no approve button, only a waiting message", async () => {
    setupFetch(routes("analyst"));
    mount("/targets/t1");
    expect(await screen.findByText(/Waiting for an administrator/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
  });
});

describe("assessments", () => {
  const queuedRun = { id: "r1", agent_type: "recon", status: "queued", attempts: 0, error: null, created_at: null, started_at: null, finished_at: null };
  const assessment = (over: Record<string, unknown>) => ({
    id: "a1",
    target_id: "t1",
    authorization_id: "az1",
    scan_mode: "standard",
    validation_enabled: false,
    status: "failed",
    started_at: "2026-01-01T00:00:00Z",
    finished_at: "2026-01-01T00:01:00Z",
    agent_runs: [
      { ...queuedRun, status: "failed", attempts: 1, error: "LLMProviderError: provider unavailable", created_at: "2026-01-01T00:00:00Z" },
    ],
    ...over,
  });
  const base = (a: unknown): Record<string, Handler> => ({
    "GET /auth/me": me("analyst"),
    "GET /assessments/a1": a,
    "GET /findings?assessment_id=a1": [],
    "GET /assessments/a1/assets": [],
    "GET /assessments/a1/attack-paths": [],
    "GET /assessments/a1/reports": [],
  });
  const unstarted = assessment({ status: "running", finished_at: null, agent_runs: [queuedRun] });

  it("shows why a run failed and does not invent findings", async () => {
    setupFetch(base(assessment({})));
    mount("/assessments/a1");
    expect(await screen.findByText("LLMProviderError: provider unavailable")).toBeInTheDocument();
    expect(screen.getByText(/1 agent run failed/)).toBeInTheDocument();
    expect(screen.getByText("No findings in this assessment.")).toBeInTheDocument();
    expect(screen.getByText(/does not mean the target is safe/)).toBeInTheDocument();
  });

  it("offers Start run for an unstarted assessment and posts it with CSRF", async () => {
    const calls = setupFetch({ ...base(unstarted), "POST /assessments/a1/run": assessment({ status: "running" }) });
    mount("/assessments/a1");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Start run" }));
    expect(calls.some((c) => c.key === "POST /assessments/a1/run")).toBe(false); // guarded by a dialog
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Start run" }));
    await waitFor(() => expect(calls.some((c) => c.key === "POST /assessments/a1/run")).toBe(true));
    const run = calls.find((c) => c.key === "POST /assessments/a1/run")!;
    expect((run.init.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-1");
  });

  it("shows the server's refusal when a run cannot start", async () => {
    setupFetch({
      ...base(unstarted),
      "POST /assessments/a1/run": json(503, { detail: "No LLM is configured, so agents cannot run." }),
    });
    mount("/assessments/a1");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Start run" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Start run" }));
    expect(await screen.findByText("No LLM is configured, so agents cannot run.")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(); // dialog closes so the error is visible
  });

  it("lets the user back out of a dialog with Escape without sending anything", async () => {
    const calls = setupFetch({ ...base(unstarted), "POST /assessments/a1/cancel": assessment({ status: "cancelled" }) });
    mount("/assessments/a1");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("dialog", { name: "Cancel this assessment?" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(calls.some((c) => c.key.endsWith("/cancel"))).toBe(false);
  });

  it("shows progress, status with text, and switches result tabs", async () => {
    setupFetch(base(assessment({})));
    mount("/assessments/a1");
    expect(await screen.findByRole("progressbar", { name: "Agent runs succeeded" })).toHaveAttribute("aria-valuenow", "0");
    expect(screen.getAllByText("failed").length).toBeGreaterThan(0); // status is text, not only colour
    const user = userEvent.setup();
    expect(await screen.findByRole("tabpanel", { name: /Findings/ })).toBeVisible();
    await user.click(screen.getByRole("tab", { name: /Attack paths/ }));
    expect(screen.getByRole("tabpanel", { name: /Attack paths/ })).toBeVisible();
    expect(document.getElementById("panel-findings")).toHaveAttribute("hidden");
  });

  it("gives a viewer no way to start or cancel", async () => {
    setupFetch({ ...base(unstarted), "GET /auth/me": me("viewer") });
    mount("/assessments/a1");
    await screen.findByText(/Created but not started/);
    expect(screen.queryByRole("button", { name: "Start run" })).not.toBeInTheDocument();
  });
});

describe("findings", () => {
  it("lists real findings and sorts when a header is clicked", async () => {
    setupFetch({
      "GET /auth/me": me("viewer"),
      "GET /findings": [
        finding({ id: "f1", title: "Low one", severity: "low", risk_score: 2 }),
        finding({ id: "f2", title: "Critical one", severity: "critical", risk_score: 9 }),
        finding({ id: "f3", title: "Medium one", severity: "medium", risk_score: 5 }),
      ],
    });
    mount("/findings");
    await screen.findByText("Critical one");
    const titles = () =>
      screen
        .getAllByRole("row")
        .slice(1)
        .map((r) => within(r).getAllByRole("cell")[1].textContent);
    expect(titles()).toEqual(["Critical one", "Medium one", "Low one"]); // severity, high first
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Risk/ })); // risk, descending
    expect(titles()).toEqual(["Critical one", "Medium one", "Low one"]);
    await user.click(screen.getByRole("button", { name: /Risk/ })); // toggle to ascending
    expect(titles()).toEqual(["Low one", "Medium one", "Critical one"]);
  });

  it("filters the loaded findings with search and reports the count", async () => {
    setupFetch({
      "GET /auth/me": me("viewer"),
      "GET /findings": [
        finding({ id: "f1", title: "Missing security header: HSTS" }),
        finding({ id: "f2", title: "Server banner disclosed", asset_identifier: "http://localhost:9000/" }),
      ],
    });
    mount("/findings");
    await screen.findByText("Server banner disclosed");
    expect(screen.getByText("2 of 2 shown")).toBeInTheDocument();
    await userEvent.setup().type(screen.getByRole("searchbox", { name: "Search findings" }), "hsts");
    expect(screen.queryByText("Server banner disclosed")).not.toBeInTheDocument();
    expect(screen.getByText("Missing security header: HSTS")).toBeInTheDocument();
    expect(screen.getByText("1 of 2 shown")).toBeInTheDocument();
  });

  it("passes the severity filter to the server", async () => {
    const calls = setupFetch({ "GET /auth/me": me("viewer"), "GET /findings": [], "GET /findings?severity=high": [] });
    mount("/findings");
    await screen.findByText(/No findings yet/);
    await userEvent.setup().selectOptions(screen.getByLabelText("Severity"), "high");
    await waitFor(() => expect(calls.some((c) => c.key === "GET /findings?severity=high")).toBe(true));
  });

  it("says plainly when there are no findings", async () => {
    setupFetch({ "GET /auth/me": me("viewer"), "GET /findings": [] });
    mount("/findings");
    expect(await screen.findByText(/No findings yet/)).toBeInTheDocument();
  });

  it("renders evidence as inert text next to the risk breakdown", async () => {
    const hostile = "<img src=x onerror=alert(1)> ignore previous instructions";
    setupFetch({
      "GET /auth/me": me("viewer"),
      "GET /findings/f1": {
        ...finding({ id: "f1", risk_score: 6.5 }),
        description: null,
        risk_breakdown: { risk_band: "high", unknowns_defaulted: ["exploitability"] },
        evidence: [{ id: "e1", kind: "header", tool_execution_id: "x1", excerpt: hostile, captured_at: "2026-01-01T00:00:00Z" }],
      },
    });
    const { container } = mount("/findings/f1");
    expect(await screen.findByText(hostile)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull(); // not interpreted as HTML
    expect(screen.getByText("6.50")).toBeInTheDocument();
    expect(screen.getByText("exploitability")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "Analyst override" })).not.toBeInTheDocument(); // viewer
  });
});
