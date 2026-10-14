import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Async, EmptyState, Notice, PageHeader, Panel, Tabs, download, fmtDate, useAsync } from "../ui";

type Format = "markdown" | "json";

export function ReportPage() {
  const { id = "" } = useParams();
  const report = useAsync(() => api.report(id), [id]);
  const [tab, setTab] = useState<Format>("markdown");

  return (
    <Async state={report}>
      {(r) => {
        const json = r.content_json ? JSON.stringify(r.content_json, null, 2) : null;
        const markdown = r.content_markdown;
        const aiSummary = (r.provenance as { ai_summary?: { status?: string } }).ai_summary;
        const shown = tab === "markdown" ? markdown : json;
        return (
          <>
            <PageHeader
              title="Report"
              sub={
                <>
                  Generated {fmtDate(r.generated_at)} · formats: {r.formats.join(", ")}
                </>
              }
              actions={
                <>
                  {markdown && (
                    <button className="secondary" onClick={() => download(`report-${r.id}.md`, markdown, "text/markdown")}>
                      Download .md
                    </button>
                  )}
                  {json && (
                    <button className="secondary" onClick={() => download(`report-${r.id}.json`, json, "application/json")}>
                      Download .json
                    </button>
                  )}
                  <Link className="btn secondary" to={`/assessments/${r.assessment_id}`}>
                    Open assessment
                  </Link>
                </>
              }
            />
            {aiSummary?.status && aiSummary.status !== "generated" && (
              <Notice kind="info">AI executive summary: {aiSummary.status}. The findings below are unaffected.</Notice>
            )}
            <div className="panel">
              <Tabs
                label="Report format"
                value={tab}
                onChange={setTab}
                tabs={[
                  { id: "markdown", label: "Markdown" },
                  { id: "json", label: "JSON" },
                ]}
              />
              <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
                {shown ? (
                  // Report text includes strings captured from targets; show it as plain text.
                  <pre className="report">{shown}</pre>
                ) : (
                  <EmptyState title={`This report was not generated in the ${tab} format.`} />
                )}
              </div>
            </div>
            <Panel title="Provenance">
              <details>
                <summary className="muted small" style={{ cursor: "pointer" }}>
                  How this report was produced
                </summary>
                <pre>{JSON.stringify(r.provenance, null, 2)}</pre>
              </details>
            </Panel>
          </>
        );
      }}
    </Async>
  );
}
