import { api } from "../api";
import { Async, Badge, Notice, PageHeader, Panel, useAsync } from "../ui";

/** Read-only view of the configuration an operator needs to know before launching anything. Never shows keys or URLs. */
export function SystemPage() {
  const system = useAsync(api.systemStatus, []);
  return (
    <>
      <PageHeader title="System status" sub="Configuration that affects what assessments can do." />
      <Async state={system}>
        {(s) => (
          <>
            {!s.llm.enabled && (
              <Notice kind="warn">
                No LLM is configured, so assessments can be created but not run. Set the <code>OFFENSIVEX_LLM_*</code>{" "}
                variables and restart the backend.
              </Notice>
            )}
            {s.allow_private_targets && (
              <Notice kind="warn">Private-network targets are allowed. Scope rules still apply to every tool call.</Notice>
            )}
            {s.allow_self_approval && (
              <Notice kind="warn">Self-approval is on: the person who submits a scope may also approve it.</Notice>
            )}
            <div className="cols">
              <Panel title="Environment">
                <dl className="facts">
                  <dt>Environment</dt>
                  <dd>{s.environment}</dd>
                  <dt>Session lifetime</dt>
                  <dd>{s.session_ttl_minutes} minutes</dd>
                </dl>
              </Panel>
              <Panel title="Agents">
                <dl className="facts">
                  <dt>LLM</dt>
                  <dd>{s.llm.enabled ? <Badge value="success" /> : <Badge value="failed" />}</dd>
                  <dt>Provider</dt>
                  <dd>{s.llm.provider ?? "—"}</dd>
                  <dt>Model</dt>
                  <dd className="mono">{s.llm.model ?? "—"}</dd>
                </dl>
              </Panel>
              <Panel title="Safety switches">
                <dl className="facts">
                  <dt>Private targets</dt>
                  <dd>{s.allow_private_targets ? "allowed" : "blocked"}</dd>
                  <dt>Self-approval</dt>
                  <dd>{s.allow_self_approval ? "allowed" : "off"}</dd>
                </dl>
              </Panel>
            </div>
          </>
        )}
      </Async>
    </>
  );
}
