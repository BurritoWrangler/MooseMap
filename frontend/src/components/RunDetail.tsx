import { useEffect, useMemo, useRef, useState } from "react";
import { api, reportDownloadUrl } from "../api/client";
import {
  targetLabel,
  type EngineEvent,
  type Finding,
  type Report,
  type Run,
  type Stage,
  type Task,
} from "../api/types";
import { useAnnouncer } from "../hooks/useAnnouncer";
import { SeverityPill, StatusBadge } from "./Badges";
import { Pipeline } from "./Pipeline";

type LogLine = { id: string; level: "info" | "warn" | "error"; text: string };

/**
 * Live dashboard for a single run. It seeds state from REST (so a page refresh
 * or late subscription still shows current state) and then applies live
 * WebSocket events for real-time updates. Status transitions are announced to
 * screen readers via the global live region.
 */
export function RunDetail({
  run,
  events,
  seq,
  onRunUpdated,
}: {
  run: Run;
  events: EngineEvent[];
  seq: number;
  onRunUpdated: (run: Run) => void;
}) {
  const [tasks, setTasks] = useState<Record<Stage, Task | undefined>>({} as never);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [status, setStatus] = useState(run.status);
  const lastSeq = useRef(0);
  const logEnd = useRef<HTMLLIElement>(null);
  const { announce } = useAnnouncer();

  // Seed from REST whenever the selected run changes.
  useEffect(() => {
    let cancelled = false;
    setStatus(run.status);
    setLogs([]);
    (async () => {
      try {
        const [t, r] = await Promise.all([
          api.getTasks(run.id),
          api.getReport(run.id),
        ]);
        if (cancelled) return;
        const map = {} as Record<Stage, Task | undefined>;
        for (const task of t) map[task.stage] = task;
        setTasks(map);
        setReport(r);
        setFindings(r.findings);
      } catch {
        // transient; live events will fill in
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [run.id, run.status]);

  // Apply new live events scoped to this run.
  useEffect(() => {
    if (seq === lastSeq.current) return;
    const fresh = events.slice(Math.max(0, events.length - (seq - lastSeq.current)));
    lastSeq.current = seq;

    for (const ev of fresh) {
      if ("run_id" in ev && ev.run_id !== run.id) continue;
      switch (ev.type) {
        case "run_status_changed":
          setStatus(ev.status);
          onRunUpdated({ ...run, status: ev.status });
          announce(`Assessment ${run.name} is now ${ev.status}.`);
          if (ev.status === "completed" || ev.status === "failed") {
            // Refresh the final report once the run ends.
            api.getReport(run.id).then((r) => {
              setReport(r);
              setFindings(r.findings);
            }).catch(() => {});
          }
          break;
        case "task_status_changed":
          setTasks((prev) => ({
            ...prev,
            [ev.stage]: {
              id: ev.task_id,
              run_id: ev.run_id,
              stage: ev.stage,
              status: ev.status,
              message: ev.message,
              started_at: null,
              finished_at: null,
            },
          }));
          break;
        case "finding_added":
          setFindings((prev) =>
            prev.some((f) => f.id === ev.finding.id) ? prev : [...prev, ev.finding],
          );
          break;
        case "log":
          setLogs((prev) => [
            ...prev.slice(-200),
            {
              id: `${ev.at}-${prev.length}`,
              level: ev.level,
              text: `[${ev.stage}] ${ev.message}`,
            },
          ]);
          break;
      }
    }
  }, [seq, events, run, announce, onRunUpdated]);

  // Keep the log scrolled to the newest line.
  useEffect(() => {
    logEnd.current?.scrollIntoView({ block: "nearest" });
  }, [logs]);

  const sortedFindings = useMemo(
    () => [...findings].sort((a, b) => b.priority - a.priority),
    [findings],
  );

  const canStart = status === "pending";
  // A report is worth exporting once the run has reached a terminal state.
  const reportReady = status === "completed" || status === "failed";

  async function handleStart() {
    try {
      await api.startRun(run.id);
      setStatus("running");
      announce(`Started assessment ${run.name}.`);
    } catch {
      announce(`Could not start assessment ${run.name}.`);
    }
  }

  return (
    <div className="stack">
      <section className="card" aria-labelledby="detail-heading">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <div>
            <h2 id="detail-heading" style={{ marginBottom: "0.2rem" }}>
              {run.name}
            </h2>
            <p className="muted mono" style={{ margin: 0 }}>
              {run.scope.join(", ")}
            </p>
          </div>
          <div className="row">
            <StatusBadge status={status} />
            {canStart && (
              <button className="btn" type="button" onClick={handleStart}>
                Start scan
              </button>
            )}
          </div>
        </div>

        {reportReady && (
          <div
            className="row"
            style={{ marginTop: "0.8rem", gap: "0.5rem" }}
            aria-label="Download report"
          >
            <span className="muted" style={{ fontSize: "0.85rem" }}>
              Export report:
            </span>
            <a
              className="btn btn-secondary"
              href={reportDownloadUrl.markdown(run.id)}
              download
            >
              ⬇ Markdown
            </a>
            <a
              className="btn btn-secondary"
              href={reportDownloadUrl.json(run.id)}
              download
            >
              ⬇ JSON
            </a>
          </div>
        )}
      </section>

      <section className="card" aria-labelledby="pipeline-heading">
        <h3 id="pipeline-heading">Live progress</h3>
        <Pipeline tasks={tasks} />
      </section>

      {report && <SummaryCard report={report} />}

      <section className="card" aria-labelledby="findings-heading">
        <h3 id="findings-heading">
          Prioritized findings{" "}
          <span className="muted">({sortedFindings.length})</span>
        </h3>
        <FindingsTable findings={sortedFindings} />
      </section>

      <section className="card" aria-labelledby="services-heading">
        <h3 id="services-heading">
          Service inventory{" "}
          <span className="muted">({report?.services.length ?? 0})</span>
        </h3>
        <ServicesTable report={report} />
      </section>

      <section className="card" aria-labelledby="log-heading">
        <h3 id="log-heading">Activity log</h3>
        <ul className="event-log" aria-label="Live activity log" aria-live="off">
          {logs.length === 0 ? (
            <li className="muted">Waiting for activity…</li>
          ) : (
            logs.map((l) => (
              <li key={l.id} className={`lvl-${l.level}`}>
                {l.text}
              </li>
            ))
          )}
          <li ref={logEnd} aria-hidden="true" />
        </ul>
      </section>
    </div>
  );
}

function SummaryCard({ report }: { report: Report }) {
  const s = report.summary;
  const metrics = [
    { l: "Targets", n: s.total_targets },
    { l: "Open ports", n: s.total_open_ports },
    { l: "Findings", n: s.total_findings },
    { l: "Actionable", n: s.actionable },
  ];
  return (
    <section className="card" aria-labelledby="summary-heading">
      <h3 id="summary-heading">Executive summary</h3>
      <div className="grid-summary">
        {metrics.map((m) => (
          <div className="metric" key={m.l}>
            <div className="n">{m.n}</div>
            <div className="l">{m.l}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function FindingsTable({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return <p className="muted">No findings recorded yet.</p>;
  }
  return (
    <table>
      <caption className="visually-hidden">
        Findings ordered by priority, highest first
      </caption>
      <thead>
        <tr>
          <th scope="col">Priority</th>
          <th scope="col">Severity</th>
          <th scope="col">Title</th>
          <th scope="col">Target</th>
          <th scope="col">Source</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <tr key={f.id}>
            <td className="mono">{f.priority.toFixed(2)}</td>
            <td>
              <SeverityPill severity={f.severity} />
            </td>
            <td>
              <div style={{ fontWeight: 600 }}>{f.title}</div>
              <div className="muted" style={{ fontSize: "0.82rem" }}>
                {f.description}
              </div>
            </td>
            <td className="mono">
              {targetLabel(f.target)}
              {f.port != null ? `:${f.port}` : ""}
            </td>
            <td className="muted">{f.source}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ServicesTable({ report }: { report: Report | null }) {
  const services = report?.services ?? [];
  if (services.length === 0) {
    return <p className="muted">No open services discovered yet.</p>;
  }
  return (
    <table>
      <caption className="visually-hidden">Discovered open services</caption>
      <thead>
        <tr>
          <th scope="col">Target</th>
          <th scope="col">Port</th>
          <th scope="col">Proto</th>
          <th scope="col">Service</th>
          <th scope="col">Product / version</th>
        </tr>
      </thead>
      <tbody>
        {services.map((svc, i) => (
          <tr key={`${targetLabel(svc.target)}-${svc.port}-${i}`}>
            <td className="mono">{targetLabel(svc.target)}</td>
            <td className="mono">{svc.port}</td>
            <td>{svc.protocol}</td>
            <td>{svc.service_name ?? "—"}</td>
            <td className="muted">
              {[svc.product, svc.version].filter(Boolean).join(" ") || "—"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
