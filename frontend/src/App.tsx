import { useEffect, useState, type ReactNode } from "react";
import { Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { capabilities, useAuth } from "./auth";
import { AssessmentDetailPage, AssessmentsPage } from "./pages/Assessments";
import { AuditPage } from "./pages/Audit";
import { FindingDetailPage, FindingsPage } from "./pages/Findings";
import { LoginPage } from "./pages/Login";
import { OverviewPage } from "./pages/Overview";
import { ReportPage } from "./pages/Reports";
import { SystemPage } from "./pages/System";
import { TargetDetailPage, TargetsPage } from "./pages/Targets";
import { EmptyState, Icon, PageHeader, ToastProvider } from "./ui";

const SECTIONS: Record<string, { label: string; to: string }> = {
  targets: { label: "Targets", to: "/targets" },
  assessments: { label: "Assessments", to: "/assessments" },
  findings: { label: "Findings", to: "/findings" },
  reports: { label: "Reports", to: "/assessments" },
  audit: { label: "Audit", to: "/audit" },
  system: { label: "System", to: "/system" },
};

function Breadcrumbs() {
  const [first, second] = useLocation().pathname.split("/").filter(Boolean);
  const section = first ? SECTIONS[first] : undefined;
  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      {!section ? (
        <span aria-current="page">Overview</span>
      ) : second ? (
        <>
          <Link to={section.to}>{section.label}</Link>
          <span className="sep" aria-hidden="true">
            /
          </span>
          <span aria-current="page">{first === "reports" ? "Report" : "Details"}</span>
        </>
      ) : (
        <span aria-current="page">{section.label}</span>
      )}
    </nav>
  );
}

function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const can = capabilities(user?.role);
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();

  // Close the drawer after navigating and on Escape.
  useEffect(() => setOpen(false), [pathname]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <div className="shell">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <div className={`scrim${open ? " open" : ""}`} onClick={() => setOpen(false)} aria-hidden="true" />
      <aside id="sidebar" className={`sidebar${open ? " open" : ""}`}>
        <Link to="/" className="brand">
          <span className="brand-mark">
            <Icon name="shield" size={14} />
          </span>
          OffensiveX
        </Link>
        <nav className="nav" aria-label="Main">
          <NavLink to="/" end>
            <Icon name="overview" />
            Overview
          </NavLink>
          <div className="nav-label">Assess</div>
          <NavLink to="/targets">
            <Icon name="target" />
            Targets
          </NavLink>
          <NavLink to="/assessments">
            <Icon name="activity" />
            Assessments
          </NavLink>
          <NavLink to="/findings">
            <Icon name="findings" />
            Findings
          </NavLink>
          <div className="nav-label">Operate</div>
          {can.audit && (
            <NavLink to="/audit">
              <Icon name="audit" />
              Audit
            </NavLink>
          )}
          <NavLink to="/system">
            <Icon name="system" />
            System
          </NavLink>
        </nav>
        <div className="sidebar-foot">
          <div className="user-chip">
            <span className="avatar" aria-hidden="true">
              {user?.username.slice(0, 2)}
            </span>
            <span className="user-meta">
              <strong>{user?.username}</strong>
              <span className="faint small">{user?.role}</span>
            </span>
          </div>
          <button className="secondary" onClick={() => void logout()}>
            <Icon name="logout" />
            Sign out
          </button>
        </div>
      </aside>
      <div className="main-col">
        <header className="topbar">
          <button
            className="ghost nav-toggle"
            aria-label={open ? "Close navigation" : "Open navigation"}
            aria-expanded={open}
            aria-controls="sidebar"
            onClick={() => setOpen(!open)}
          >
            <Icon name={open ? "close" : "menu"} size={20} />
          </button>
          <Breadcrumbs />
        </header>
        <main id="main" className="content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}

export function App() {
  const { user, ready } = useAuth();
  if (!ready)
    return (
      <div className="boot" role="status">
        Loading…
      </div>
    );
  if (!user) return <LoginPage />;
  return (
    <ToastProvider>
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
          <Route path="/system" element={<SystemPage />} />
          <Route
            path="*"
            element={
              <>
                <PageHeader title="Page not found" />
                <EmptyState title="There is nothing at this address.">
                  Use the navigation to pick a section.
                </EmptyState>
              </>
            }
          />
        </Routes>
      </Layout>
    </ToastProvider>
  );
}
