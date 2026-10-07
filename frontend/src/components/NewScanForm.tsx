import { useId, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import type { Run } from "../api/types";
import { useAnnouncer } from "../hooks/useAnnouncer";

/**
 * Accessible "new scan" form.
 * - Each field has an associated <label> and descriptive hint via aria-describedby.
 * - Validation errors are surfaced in an alert region and the invalid field is
 *   marked aria-invalid and focused, so keyboard/SR users are taken to the problem.
 */
export function NewScanForm({ onCreated }: { onCreated: (run: Run) => void }) {
  const nameId = useId();
  const scopeId = useId();
  const scopeHintId = useId();
  const errorId = useId();

  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const [start, setStart] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<{ message: string; details: string[] } | null>(
    null,
  );

  const nameRef = useRef<HTMLInputElement>(null);
  const scopeRef = useRef<HTMLTextAreaElement>(null);
  const { announce } = useAnnouncer();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!name.trim()) {
      setError({ message: "Please provide a name for this assessment.", details: [] });
      nameRef.current?.focus();
      return;
    }
    if (!scope.trim()) {
      setError({
        message: "Please provide at least one in-scope target.",
        details: [],
      });
      scopeRef.current?.focus();
      return;
    }

    setSubmitting(true);
    try {
      const run = await api.createRun({ name: name.trim(), scope, start });
      announce(
        `Assessment "${run.name}" created${start ? " and started" : ""}.`,
      );
      setName("");
      setScope("");
      onCreated(run);
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ message: err.message, details: err.details });
        scopeRef.current?.focus();
      } else {
        setError({ message: "Something went wrong creating the scan.", details: [] });
      }
    } finally {
      setSubmitting(false);
    }
  }

  const hasError = error !== null;

  return (
    <section className="card" aria-labelledby="new-scan-heading">
      <h2 id="new-scan-heading">New assessment</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Authorized testing only. Only enter assets you are permitted to test.
      </p>

      <form onSubmit={handleSubmit} noValidate>
        {hasError && (
          <div className="alert alert-error" role="alert" id={errorId}>
            <strong>{error!.message}</strong>
            {error!.details.length > 0 && (
              <ul style={{ margin: "0.4rem 0 0", paddingLeft: "1.2rem" }}>
                {error!.details.map((d) => (
                  <li key={d}>{d}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <div className="field">
          <label htmlFor={nameId}>Assessment name</label>
          <input
            id={nameId}
            ref={nameRef}
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoComplete="off"
            aria-invalid={hasError && !name.trim()}
            aria-describedby={hasError ? errorId : undefined}
            placeholder="Acme external perimeter"
          />
        </div>

        <div className="field">
          <label htmlFor={scopeId}>Scope</label>
          <textarea
            id={scopeId}
            ref={scopeRef}
            value={scope}
            onChange={(e) => setScope(e.target.value)}
            aria-describedby={`${scopeHintId}${hasError ? ` ${errorId}` : ""}`}
            aria-invalid={hasError}
            placeholder={"192.0.2.0/24\nexample.com\n*.staging.example.com"}
          />
          <p className="hint" id={scopeHintId}>
            IPs, CIDR blocks, and FQDNs — separated by new lines, spaces, or
            commas. Use <span className="mono">*.domain</span> to include
            subdomains.
          </p>
        </div>

        <div className="field">
          <label className="row" style={{ fontWeight: 400 }}>
            <input
              type="checkbox"
              checked={start}
              onChange={(e) => setStart(e.target.checked)}
            />
            Start scanning immediately
          </label>
        </div>

        <button className="btn" type="submit" disabled={submitting}>
          {submitting ? (
            <>
              <span className="spinner" aria-hidden="true" /> Creating…
            </>
          ) : (
            "Create assessment"
          )}
        </button>
      </form>
    </section>
  );
}
