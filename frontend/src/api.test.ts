import { ApiError, api, setCsrfToken, setUnauthorizedHandler } from "./api";

const fetchMock = vi.fn();
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const session = { user: { id: "u1", username: "alice", role: "admin" }, csrf_token: "csrf-1", expires_at: "x" };

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  setCsrfToken(null);
  setUnauthorizedHandler(null);
  localStorage.clear();
  sessionStorage.clear();
});

describe("api client", () => {
  it("sends the CSRF token on mutations, never on reads, and keeps credentials same-origin", async () => {
    fetchMock.mockResolvedValueOnce(json(200, session));
    await api.login("alice", "pw");
    fetchMock.mockResolvedValueOnce(json(201, { id: "t1" }));
    await api.createTarget({ name: "n", type: "web", default_exposure: "low", default_criticality: "low" });
    fetchMock.mockResolvedValueOnce(json(200, []));
    await api.targets();

    const [, post] = fetchMock.mock.calls[1];
    expect(post.headers["X-CSRF-Token"]).toBe("csrf-1");
    expect(post.credentials).toBe("same-origin");
    const [, read] = fetchMock.mock.calls[2];
    expect(read.headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("never persists the password, session or CSRF token in browser storage", async () => {
    fetchMock.mockResolvedValueOnce(json(200, session));
    await api.login("alice", "super-secret-password");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.cookie).not.toContain("csrf-1");
  });

  it("turns server errors into readable messages", async () => {
    fetchMock.mockResolvedValueOnce(json(422, { detail: "Target has no approved authorization." }));
    await expect(api.runAssessment("a1")).rejects.toMatchObject({
      status: 422,
      message: "Target has no approved authorization.",
    });

    fetchMock.mockResolvedValueOnce(
      json(422, { errors: [{ loc: ["body", "entry_point"], msg: "must be http(s)", type: "x" }] }),
    );
    await expect(api.targets()).rejects.toThrow("entry_point: must be http(s)");
  });

  it("reports an unreachable backend instead of hanging or throwing a raw error", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    const err = await api.targets().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(0);
    expect((err as ApiError).message).toMatch(/backend running/);
  });

  it("signals an expired session on 401, but not for the login/me probes", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    fetchMock.mockResolvedValueOnce(json(401, { detail: "Authentication required." }));
    await expect(api.overview()).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);

    fetchMock.mockResolvedValueOnce(json(401, { detail: "Invalid username or password." }));
    await expect(api.login("a", "b")).rejects.toThrow("Invalid username or password.");
    fetchMock.mockResolvedValueOnce(json(401, { detail: "Authentication required." }));
    await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("builds filtered queries without empty parameters", async () => {
    fetchMock.mockResolvedValue(json(200, []));
    await api.findings({ assessment_id: "a1", status: "", severity: "high" });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/findings?assessment_id=a1&severity=high");
  });
});
