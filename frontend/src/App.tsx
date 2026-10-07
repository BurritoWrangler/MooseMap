import { useCallback, useEffect, useState } from "react";
import { api } from "./api/client";
import type { Run } from "./api/types";
import { NewScanForm } from "./components/NewScanForm";
import { Readiness } from "./components/Readiness";
import { RunDetail } from "./components/RunDetail";
import { RunList } from "./components/RunList";
import { useEventStream } from "./hooks/useEventStream";

export default function App() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const { connection, events, seq } = useEventStream();

  const refreshRuns = useCallback(async () => {
    try {
      const list = await api.listRuns();
      setRuns(list);
      setSelectedId((cur) => cur ?? list[0]?.id ?? null);
    } catch {
      // backend may not be up yet; the connection indicator reflects this
    }
  }, []);

  useEffect(() => {
    refreshRuns();
  }, [refreshRuns]);

  const selectedRun = runs.find((r) => r.id === selectedId) ?? null;

  const handleCreated = useCallback((run: Run) => {
    setRuns((prev) => [run, ...prev.filter((r) => r.id !== run.id)]);
    setSelectedId(run.id);
  }, []);

  const handleRunUpdated = useCallback((updated: Run) => {
    setRuns((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
  }, []);

  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>

      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            🫎
          </span>
          <span>MooseMap</span>
          <span
            className="badge"
            style={{ fontWeight: 600 }}
            title="Authorized testing only"
          >
            authorized use only
          </span>
        </div>
        <ConnectionIndicator connection={connection} />
      </header>

      <div className="layout">
        <nav aria-label="Readiness, new scan, and assessments" className="stack">
          <Readiness />
          <NewScanForm onCreated={handleCreated} />
          <RunList
            runs={runs}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        </nav>

        <main id="main" aria-live="off">
          {selectedRun ? (
            <RunDetail
              key={selectedRun.id}
              run={selectedRun}
              events={events}
              seq={seq}
              onRunUpdated={handleRunUpdated}
            />
          ) : (
            <section className="card" aria-labelledby="welcome-heading">
              <h2 id="welcome-heading">Run an external assessment</h2>
              <p className="muted">
                MooseMap drives a suite of recon and scanning tools through a
                staged pipeline, tracks progress live, and prioritizes
                exploitable findings into a report.
              </p>
              <ol className="workflow-steps">
                <li>
                  <strong>Check readiness.</strong> Confirm your scanning tools
                  are installed and resolve correctly (left panel).
                </li>
                <li>
                  <strong>Define scope &amp; start.</strong> Enter the IPs, CIDRs,
                  and domains you are authorized to test, then launch the scan.
                </li>
                <li>
                  <strong>Track live.</strong> Watch each stage and findings
                  appear in real time.
                </li>
                <li>
                  <strong>Export the report.</strong> Download the prioritized
                  findings as Markdown or JSON when the run completes.
                </li>
              </ol>
              <p className="muted">
                Reminder: only scan assets you are explicitly authorized to test.
              </p>
            </section>
          )}
        </main>
      </div>
    </div>
  );
}

function ConnectionIndicator({
  connection,
}: {
  connection: "connecting" | "open" | "closed";
}) {
  const label =
    connection === "open"
      ? "Live"
      : connection === "connecting"
        ? "Connecting"
        : "Offline";
  const statusClass =
    connection === "open"
      ? "status-completed"
      : connection === "connecting"
        ? "status-running"
        : "status-failed";
  return (
    <span className="conn" role="status" aria-live="polite">
      <span className={`badge ${statusClass}`}>
        <span className="dot" aria-hidden="true" />
        {label}
      </span>
    </span>
  );
}
