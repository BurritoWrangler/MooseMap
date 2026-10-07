import type { RunStatus, Severity, TaskStatus } from "../api/types";

/**
 * Status badge. Conveys state with a text label *and* a colored dot, never by
 * color alone, satisfying WCAG 1.4.1 (use of color).
 */
export function StatusBadge({
  status,
}: {
  status: RunStatus | TaskStatus;
}) {
  return (
    <span className={`badge status-${status}`}>
      <span className="dot" aria-hidden="true" />
      {status}
    </span>
  );
}

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Severity pill with text label; color is supplementary. */
export function SeverityPill({ severity }: { severity: Severity }) {
  return (
    <span className={`sev sev-${severity}`}>
      <span aria-hidden="true">●</span>
      {SEV_LABEL[severity]}
    </span>
  );
}
