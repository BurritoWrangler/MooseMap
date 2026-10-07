import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api/client";
import type { ToolState, ToolStatus } from "../api/types";

/**
 * Preflight "readiness" panel — the tool doctor in the GUI.
 *
 * Shows each external scanning tool's health before a scan is run, so the
 * operator knows which pipeline stages will actually do work (and catches the
 * Kali `httpx` shadowing problem up front). Mirrors `moosemap tools`.
 */
export function Readiness() {
  const [tools, setTools] = useState<ToolStatus[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setTools(await api.getTools());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not load tool status.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const okCount = tools?.filter((t) => t.state === "ok").length ?? 0;
  const total = tools?.length ?? 0;

  return (
    <section className="card" aria-labelledby="readiness-heading">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2 id="readiness-heading" style={{ margin: 0 }}>
          Scanner readiness
        </h2>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={refresh}
          disabled={loading}
        >
          {loading ? "Checking…" : "Re-check"}
        </button>
      </div>

      <p className="muted" style={{ marginTop: "0.4rem" }}>
        {tools
          ? `${okCount} of ${total} tools ready. Missing tools skip their stage; the scan still runs.`
          : "Checking which scanning tools are installed…"}
      </p>

      {error && (
        <div className="alert alert-error" role="alert">
          {error}
        </div>
      )}

      {tools && (
        <ul className="tool-list" aria-label="External scanning tools">
          {tools.map((t) => (
            <ToolRow key={t.name} tool={t} />
          ))}
        </ul>
      )}
    </section>
  );
}

const STATE_LABEL: Record<ToolState, string> = {
  ok: "Ready",
  wrong: "Wrong tool",
  missing: "Missing",
};

// Reuse existing status badge colors: ok=green, wrong=amber(warn), missing=muted.
const STATE_BADGE: Record<ToolState, string> = {
  ok: "status-completed",
  wrong: "tool-warn",
  missing: "status-skipped",
};

function ToolRow({ tool }: { tool: ToolStatus }) {
  const needsAttention = tool.state !== "ok";
  return (
    <li className="tool-row">
      <div className="row" style={{ justifyContent: "space-between", gap: "0.5rem" }}>
        <span className="mono" style={{ fontWeight: 600 }}>
          {tool.name}
        </span>
        <span className={`badge ${STATE_BADGE[tool.state]}`}>
          <span className="dot" aria-hidden="true" />
          {STATE_LABEL[tool.state]}
        </span>
      </div>
      <div className="muted" style={{ fontSize: "0.82rem" }}>
        {tool.role}
      </div>
      {tool.resolved_path && (
        <div className="muted mono" style={{ fontSize: "0.78rem" }}>
          {tool.resolved_path}
        </div>
      )}
      {needsAttention && (
        <div className="tool-detail">
          <div>{tool.detail}</div>
          <div className="muted mono" style={{ fontSize: "0.78rem", marginTop: "0.2rem" }}>
            {tool.install_hint}
          </div>
        </div>
      )}
    </li>
  );
}
