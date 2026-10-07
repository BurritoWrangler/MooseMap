// Thin typed fetch wrapper around the MooseMap REST API.
// Uses same-origin relative URLs; the Vite dev proxy / Rust static server make
// `/api/...` resolve to the backend in both dev and production.

import type { Report, Run, Task, ToolStatus } from "./types";

/** An API error carrying the server's structured detail, if any. */
export class ApiError extends Error {
  status: number;
  details: string[];
  constructor(message: string, status: number, details: string[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "content-type": "application/json" },
    ...init,
  });

  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    let details: string[] = [];
    try {
      const body = await res.json();
      if (body && typeof body.error === "string") message = body.error;
      if (Array.isArray(body?.details)) details = body.details;
    } catch {
      // non-JSON error body; keep default message
    }
    throw new ApiError(message, res.status, details);
  }

  // 204/empty bodies
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  listRuns: () => request<Run[]>("/api/runs"),

  getRun: (id: string) => request<Run>(`/api/runs/${id}`),

  createRun: (payload: { name: string; scope: string; start: boolean }) =>
    request<Run>("/api/runs", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  startRun: (id: string) =>
    request<{ started: string }>(`/api/runs/${id}/start`, { method: "POST" }),

  getTasks: (id: string) => request<Task[]>(`/api/runs/${id}/tasks`),

  getReport: (id: string) => request<Report>(`/api/runs/${id}/report`),

  /** Tool "doctor": per-tool health used by the readiness panel. */
  getTools: () => request<ToolStatus[]>("/api/tools"),
};

/** Direct download URLs for a run's report. Used as plain anchor hrefs so the
 *  browser handles the file download via the Content-Disposition header. */
export const reportDownloadUrl = {
  json: (id: string) => `/api/runs/${id}/report.json`,
  markdown: (id: string) => `/api/runs/${id}/report.md`,
};
