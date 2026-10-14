import { useState, type FormEvent } from "react";
import { useAuth } from "../auth";
import { ErrorBox, Icon, useAction, useDocumentTitle } from "../ui";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const action = useAction();
  useDocumentTitle("Sign in");

  async function submit(event: FormEvent) {
    event.preventDefault();
    await action.run(() => login(username.trim(), password));
    setPassword(""); // never keep the password around once it has been sent
  }

  return (
    <main className="login">
      <form onSubmit={submit} className="login-card" aria-label="Sign in">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="shield" size={14} />
          </span>
          OffensiveX
        </div>
        <div>
          <h1>Sign in</h1>
          <p className="muted">Authorized security assessments only.</p>
        </div>
        <div className="stack-gap">
          <label>
            Username
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
              autoFocus
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
        </div>
        {action.error && <ErrorBox message={action.error} />}
        <button type="submit" disabled={action.busy}>
          {action.busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="faint small">
          There is no default account. An operator creates the first administrator with{" "}
          <code>offensivex admin create-user</code>.
        </p>
      </form>
    </main>
  );
}
