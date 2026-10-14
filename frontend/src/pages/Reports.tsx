import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { Async, Notice, Section, download, fmtDate, useAsync } from "../ui";

export function ReportPage() {
  const { id = "" } = useParams();
  const report = useAsync(() => api.report(id), [id]);
  const [tab, setTab] = useState<"markdown" | "json">("markdown");

  return (
    <>
      <Async state={report}>
        {(r) => {
          const json = r.content_json ? JSON.stringify(r.content_json, null, 2) : null;
          const markdown = r.content_markdown;
          const aiSummary = (r.provenance as { ai_summary?: { status?: string } }).ai_summary;
          const shown = tab === "markdown" ? markdown : json;
          return (
            <>
              <p>
                <Link to={`/assessments/${r.assessment_id}`}>← Assessment</Link>
              </p>
              <h1>Report</h1>
              <p className="muted">
                Generated {fmtDate(r.generated_at)} · formats: {r.formats.join(", ")}
              </p>
              {aiSummary?.status && aiSummary.status !== "generated" && (
                <Notice kind="info">AI executive summary: {aiSummary.status}. The findings below are unaffected.</Notice>
              )}
              <Section
                title="Content"
                actions={
                  <div className="row">
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
                  </div>
                }
              >
                <div className="tabs" role="tablist">
                  <button role="tab" aria-selected={tab === "markdown"} onClick={() => setTab("markdown")}>
                    Markdown
                  </button>
                  <button role="tab" aria-selected={tab === "json"} onClick={() => setTab("json")}>
                    JSON
                  </button>
                </div>
                {shown ? (
                  // Report text includes strings captured from targets; show it as plain text.
                  <pre className="report">{shown}</pre>
                ) : (
                  <p className="empty">This report was not generated in the {tab} format.</p>
                )}
              </Section>
            </>
          );
        }}
      </Async>
    </>
  );
}
