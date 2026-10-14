import { useState, type ReactNode } from "react";
import { Link, NavLink, Route, Routes } from "react-router-dom";
import { capabilities, useAuth } from "./auth";
import { AssessmentDetailPage, AssessmentsPage } from "./pages/Assessments";
import { AuditPage } from "./pages/Audit";
import { FindingDetailPage, FindingsPage } from "./pages/Findings";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { ReportPage } from "./pages/Reports";
import { TargetDetailPage, TargetsPage } from "./pages/Targets";

function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const can = capabilities(user?.role);
  const [open, setOpen] = useState(false);
  return (
    <>
      <header className="topbar">
        <Link to="/" className="brand">
          OffensiveX
        </Link>
        <button className="secondary menu" aria-expanded={open} onClick={() => setOpen(!open)}>
          Menu
        </button>
        <nav className={open ? "open" : ""} aria-label="Main" onClick={() => setOpen(false)}>
          <NavLink to="/" end>
            Overview
          </NavLink>
          <NavLink to="/targets">Targets</NavLink>
          <NavLink to="/assessments">Assessments</NavLink>
          <NavLink to="/findings">Findings</NavLink>
          {can.audit && <NavLink to="/audit">Audit</NavLink>}
        </nav>
        <div className="who">
          <span>
            {user?.username} <span className="badge">{user?.role}</span>
          </span>
          <button className="secondary" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </header>
      <main className="content">{children}</main>
    </>
  );
}

export function App() {
  const { user, ready } = useAuth();
  if (!ready) return <p className="muted center">Loading…</p>;
  if (!user) return <LoginPage />;
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/targets/:id" element={<TargetDetailPage />} />
        <Route path="/assessments" element={<AssessmentsPage />} />
        <Route path="/assessments/:id" element={<AssessmentDetailPage />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
        <Route path="/reports/:id" element={<ReportPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="*" element={<p className="empty">Page not found.</p>} />
      </Routes>
    </Layout>
  );
}
