"use client";

import { useState } from "react";

import { Pill } from "@/components/app/ui";
import { createApiClient, type ScanAnalysis } from "@/lib/api/client";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

/**
 * Correlation and planning derived from stored rows.
 *
 * Nothing here is generated on the client: the backend correlates persisted
 * findings, reports which tools were available, and states whether the plan came
 * from a model or from the deterministic fallback.
 */
export function ScanAnalysisPanel({ scanId }: { scanId: string }) {
  const [analysis, setAnalysis] = useState<ScanAnalysis | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onRun() {
    setPending(true);
    setError(null);
    const api = createApiClient(getSupabaseBrowserClient());
    const response = await api.getAnalysis(scanId);
    setPending(false);
    if (response.error) {
      setError(response.error.message);
      return;
    }
    setAnalysis(response.data);
  }

  const unavailable = analysis
    ? Object.entries(analysis.tools_available)
        .filter(([, available]) => !available)
        .map(([tool]) => tool)
    : [];

  return (
    <section>
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="mono text-ash">Analysis</h2>
        <button
          type="button"
          onClick={onRun}
          disabled={pending}
          className="btn btn-outline h-8 px-3 disabled:opacity-50"
        >
          {pending ? "Reading…" : analysis ? "Re-read" : "Show analysis"}
        </button>
      </div>

      {error ? (
        <p className="border border-red-500/30 bg-red-500/10 px-3 py-2 font-mono text-[11px] text-red-200">
          {error}
        </p>
      ) : null}

      {!analysis ? (
        <div className="panel p-5 font-mono text-[11.5px] leading-relaxed text-ash">
          Nothing derived has been loaded yet. Analysis is computed from the
          findings already stored for this run.
        </div>
      ) : (
        <div className="panel divide-y divide-hairline">
          <div className="px-4 py-3">
            <p className="mono-sm mb-2 text-ash">Findings by severity</p>
            {analysis.summary.total === 0 ? (
              <p className="font-mono text-[11px] text-ash">
                No findings rows are stored for this run.
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {Object.entries(analysis.summary.by_severity).map(([severity, count]) => (
                  <span
                    key={severity}
                    className="border border-hairline px-2 py-1 font-mono text-[10px] uppercase tracking-[0.12em] text-muted"
                  >
                    {severity} {count}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="px-4 py-3">
            <p className="mono-sm mb-2 text-ash">Observations</p>
            {analysis.observations.length === 0 ? (
              <p className="font-mono text-[11px] leading-relaxed text-ash">
                No cross-finding observation was derived. Correlations only appear
                when the stored findings actually share a file or a scanner.
              </p>
            ) : (
              <ul className="space-y-3">
                {analysis.observations.map((observation, index) => (
                  <li key={`${observation.kind}-${index}`}>
                    <div className="flex items-center gap-2">
                      <Pill tone="muted">{observation.kind.replace(/_/g, " ")}</Pill>
                      <p className="text-[12.5px] text-fog">{observation.title}</p>
                    </div>
                    <p className="mt-1 font-mono text-[10.5px] leading-relaxed text-ash">
                      {observation.body}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="px-4 py-3">
            <p className="mono-sm mb-2 text-ash">
              Plan source: {analysis.plan.source}
            </p>
            <ul className="space-y-1 font-mono text-[10.5px] text-muted">
              {analysis.plan.steps.map((step) => (
                <li key={step.tool}>
                  · {step.tool} — {step.reason}
                </li>
              ))}
            </ul>
            {analysis.plan.source !== "model" ? (
              <p className="mt-2 font-mono text-[10px] leading-relaxed text-ash">
                The deterministic fallback produced this plan. No model gateway
                returned one, so it reflects registry availability only.
              </p>
            ) : null}
            {analysis.plan.rejected.length > 0 ? (
              <p className="mt-2 font-mono text-[10px] text-amber-200">
                Rejected by validation: {analysis.plan.rejected.join(", ")}
              </p>
            ) : null}
            {unavailable.length > 0 ? (
              <p className="mt-2 font-mono text-[10px] leading-relaxed text-ash">
                Not available on this worker: {unavailable.join(", ")}. Those checks
                did not run, so treat their absence as missing coverage.
              </p>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}
