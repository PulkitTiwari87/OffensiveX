import { useState } from "react";
import { api } from "../api";
import { Async, Badge, EmptyState, PageHeader, Panel, SearchInput, fmtDate, useAsync } from "../ui";

export function AuditPage() {
  const [action, setAction] = useState("");
  const [query, setQuery] = useState("");
  const entries = useAsync(() => api.audit({ action: action || undefined, limit: 200 }), [action]);
  const needle = query.trim().toLowerCase();
  const visible = (entries.data ?? []).filter(
    (e) =>
      !needle ||
      [e.actor_username ?? "", e.action, e.outcome, e.target_type ?? "", e.target_id ?? ""].some((s) =>
        s.toLowerCase().includes(needle),
      ),
  );

  return (
    <>
      <PageHeader title="Audit activity" sub="Who did what, and whether it was allowed. Most recent first." />
      <div className="toolbar" role="group" aria-label="Filter audit activity">
        <SearchInput value={query} onChange={setQuery} label="Search audit activity" placeholder="Search actor, action, subject" />
        <label>
          Action
          <input value={action} onChange={(e) => setAction(e.target.value)} placeholder="e.g. pipeline.run" />
        </label>
        {entries.data && (
          <span className="result-count" aria-live="polite">
            {visible.length} of {entries.data.length} shown
          </span>
        )}
      </div>
      {/* Visible only to roles with audit:read; the server answers 403 to everyone else. */}
      <Panel flush>
        <Async
          state={entries}
          empty={(e) => e.length === 0}
          emptyContent={<EmptyState title="No audit events match." />}
        >
          {() =>
            visible.length === 0 ? (
              <EmptyState title="No audit events match your search." />
            ) : (
              <div className="table-wrap">
                <table className="stack">
                  <thead>
                    <tr>
                      <th>When</th>
                      <th>Actor</th>
                      <th>Action</th>
                      <th>Outcome</th>
                      <th>Subject</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((e) => (
                      <tr key={e.id}>
                        <td data-label="When">{fmtDate(e.occurred_at)}</td>
                        <td data-label="Actor">{e.actor_username ?? "—"}</td>
                        <td className="mono" data-label="Action">
                          {e.action}
                        </td>
                        <td data-label="Outcome">
                          <Badge value={e.outcome} />
                        </td>
                        <td className="mono" data-label="Subject">
                          {e.target_type ? `${e.target_type} ${e.target_id ?? ""}` : "—"}
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
