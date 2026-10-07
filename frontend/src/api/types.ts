// Shared types mirroring the Rust API DTOs (moosemap-core / moosemap-server).
// Kept in one place so components stay honest about the server contract.

export type RunStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type TaskStatus =
  | "queued"
  | "running"
  | "done"
  | "failed"
  | "skipped";

export type Stage =
  | "discovery"
  | "port_scan"
  | "service_enum"
  | "web_recon"
  | "vuln_scan"
  | "prioritize"
  | "report";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Exploitability =
  | "none"
  | "theoretical"
  | "proof_of_concept"
  | "active";

export type Target = { Ip: string } | { Host: string };

export interface Run {
  id: string;
  name: string;
  scope: string[];
  status: RunStatus;
  created_at: string;
  updated_at: string;
}

export interface Task {
  id: string;
  run_id: string;
  stage: Stage;
  status: TaskStatus;
  message: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface Service {
  target: Target;
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered";
  service_name: string | null;
  product: string | null;
  version: string | null;
}

export interface Finding {
  id: string;
  target: Target;
  port: number | null;
  title: string;
  description: string;
  severity: Severity;
  exploitability: Exploitability;
  source: string;
  references: string[];
  priority: number;
  discovered_at: string;
}

export interface Summary {
  total_targets: number;
  total_open_ports: number;
  total_findings: number;
  by_severity: Record<string, number>;
  actionable: number;
  top_priorities: string[];
}

export interface Report {
  run_id: string;
  name: string;
  scope: string[];
  generated_at: string;
  summary: Summary;
  services: Service[];
  findings: Finding[];
}

/** Health of an external scanning tool, from the backend "doctor". */
export type ToolState = "ok" | "missing" | "wrong";

export interface ToolStatus {
  name: string;
  /** Binary MooseMap would actually invoke (after env override), if resolvable. */
  resolved_path: string | null;
  state: ToolState;
  /** Human-readable detail (e.g. the Python-httpx warning, or why it's missing). */
  detail: string;
  /** What this tool contributes to the pipeline. */
  role: string;
  /** How to install it on Kali/Debian. */
  install_hint: string;
}

// WebSocket event shapes (discriminated by `type`).
export type EngineEvent =
  | { type: "connected" }
  | { type: "lagged" }
  | { type: "run_status_changed"; run_id: string; status: RunStatus; at: string }
  | {
      type: "task_status_changed";
      run_id: string;
      task_id: string;
      stage: Stage;
      status: TaskStatus;
      message: string | null;
      at: string;
    }
  | {
      type: "log";
      run_id: string;
      stage: Stage;
      level: "info" | "warn" | "error";
      message: string;
      at: string;
    }
  | { type: "finding_added"; run_id: string; finding: Finding; at: string };

export const STAGE_ORDER: Stage[] = [
  "discovery",
  "port_scan",
  "service_enum",
  "web_recon",
  "vuln_scan",
  "prioritize",
  "report",
];

export const STAGE_LABELS: Record<Stage, string> = {
  discovery: "Discovery",
  port_scan: "Port scan",
  service_enum: "Service enum",
  web_recon: "Web recon",
  vuln_scan: "Vulnerability scan",
  prioritize: "Prioritize",
  report: "Report",
};

export function targetLabel(t: Target): string {
  return "Ip" in t ? t.Ip : t.Host;
}
