import { useState } from "react";
import { api } from "../api";
import { Async, Badge, fmtDate, useAsync } from "../ui";

export function AuditPage() {
  const [action, setAction] = useState("");
  const entries = useAsync(() => api.audit({ action: action || undefined, limit: 200 }), [action]);

  return (
    <>
      <h1>Audit activity</h1>
      <div className="filters">
        <label>
          Action
          <input value={action} onChange={(e) => setAction(e.target.value)} placeholder="e.g. pipeline.run" />
        </label>
      </div>
      {/* Visible only to roles with audit:read; the server answers 403 to everyone else. */}
      <Async state={entries} empty={(e) => e.length === 0}>
        {(list) => (
          <div className="table-wrap">
            <table>
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
                {list.map((e) => (
                  <tr key={e.id}>
                    <td>{fmtDate(e.occurred_at)}</td>
                    <td>{e.actor_username ?? "—"}</td>
                    <td>{e.action}</td>
                    <td>
                      <Badge value={e.outcome} />
                    </td>
                    <td className="mono">
                      {e.target_type ? `${e.target_type} ${e.target_id ?? ""}` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Async>
    </>
  );
}
