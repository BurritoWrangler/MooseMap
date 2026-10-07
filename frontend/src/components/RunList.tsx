import type { Run } from "../api/types";
import { StatusBadge } from "./Badges";

/**
 * Sidebar list of assessments. Each item is a real <button> so it's reachable
 * by keyboard and exposes selection state via aria-current.
 */
export function RunList({
  runs,
  selectedId,
  onSelect,
}: {
  runs: Run[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <section className="card" aria-labelledby="runs-heading">
      <h2 id="runs-heading">Assessments</h2>
      {runs.length === 0 ? (
        <p className="muted">No assessments yet. Create one to get started.</p>
      ) : (
        <ul className="run-list">
          {runs.map((run) => (
            <li key={run.id}>
              <button
                type="button"
                aria-current={run.id === selectedId}
                onClick={() => onSelect(run.id)}
              >
                <span>
                  <span style={{ fontWeight: 600 }}>{run.name}</span>
                  <br />
                  <span className="muted mono" style={{ fontSize: "0.78rem" }}>
                    {run.scope.join(", ") || "(no scope)"}
                  </span>
                </span>
                <StatusBadge status={run.status} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
