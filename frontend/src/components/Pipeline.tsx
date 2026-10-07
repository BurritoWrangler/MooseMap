import {
  STAGE_LABELS,
  STAGE_ORDER,
  type Stage,
  type Task,
  type TaskStatus,
} from "../api/types";
import { StatusBadge } from "./Badges";

const ICONS: Record<TaskStatus, string> = {
  queued: "○",
  running: "",
  done: "✓",
  failed: "✕",
  skipped: "–",
};

/**
 * Vertical pipeline tracker showing each stage's live status. Rendered as an
 * ordered list so assistive tech conveys sequence; each item is labelled with
 * stage name + status text (not just an icon).
 */
export function Pipeline({ tasks }: { tasks: Record<Stage, Task | undefined> }) {
  return (
    <ol className="pipeline" aria-label="Assessment pipeline stages">
      {STAGE_ORDER.map((stage) => {
        const task = tasks[stage];
        const status: TaskStatus = task?.status ?? "queued";
        return (
          <li key={stage} className={`stage ${status}`}>
            <span className="icon" aria-hidden="true">
              {status === "running" ? (
                <span className="spinner" />
              ) : (
                ICONS[status]
              )}
            </span>
            <span>
              <strong>{STAGE_LABELS[stage]}</strong>
              {task?.message ? (
                <span className="stage-msg"> — {task.message}</span>
              ) : null}
            </span>
            <StatusBadge status={status} />
          </li>
        );
      })}
    </ol>
  );
}
