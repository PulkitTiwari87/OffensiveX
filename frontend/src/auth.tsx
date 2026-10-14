import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, setCsrfToken, setUnauthorizedHandler, type Role, type User } from "./api";

interface AuthValue {
  user: User | null;
  /** false until the first /auth/me answer, so we don't flash the login page on reload */
  ready: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    // The session cookie is HttpOnly, so whether we are logged in is a question
    // for the server. This also re-issues the in-memory CSRF token after a reload.
    api.me().then(
      (s) => setUser(s.user),
      () => setUser(null),
    ).finally(() => setReady(true));
    setUnauthorizedHandler(() => setUser(null));
    return () => setUnauthorizedHandler(null);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const session = await api.login(username, password);
    setUser(session.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setCsrfToken(null);
      setUser(null);
    }
  }, []);

  const value = useMemo(() => ({ user, ready, login, logout }), [user, ready, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

/**
 * What to *show* for a role. This only decides which controls are rendered; it is
 * not authorization — the server enforces every permission and a hidden button
 * is never the only thing standing between a viewer and a restricted action.
 */
export function capabilities(role: Role | undefined) {
  return {
    write: role === "analyst" || role === "admin",
    decide: role === "admin",
    audit: role === "admin",
  };
}
