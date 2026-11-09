"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createApiClient } from "@/lib/api/client";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

type RunSummary = {
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  runtime_ms: number;
  meta: { tools_ran: string[]; tools_not_ran: Record<string, string> };
};

/**
 * Executes the versioned corpus on the worker that serves this deployment.
 *
 * The counts come from that real execution; a tool that is not installed is
 * listed as not run rather than counted as a pass.
 */
export function RunBenchmarkButton({ workspaceId }: { workspaceId: string }) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<RunSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onRun() {
    setPending(true);
    setError(null);
    setResult(null);

    const api = createApiClient(getSupabaseBrowserClient());
    const response = await api.runBenchmark(workspaceId);
    setPending(false);

    if (response.error) {
      setError(response.error.message);
      return;
    }

    setResult(response.data.result as unknown as RunSummary);
    router.refresh();
  }

  return (
    <div>
      <button
        type="button"
        onClick={onRun}
        disabled={pending}
        className="btn btn-primary h-9 px-3 disabled:opacity-50"
      >
        {pending ? "Scanning corpus…" : "Run benchmark"}
      </button>

      {error ? (
        <p className="mt-3 border border-red-500/30 bg-red-500/10 px-3 py-2 font-mono text-[11px] text-red-200">
          {error}
        </p>
      ) : null}

      {result ? (
        <p className="mt-3 font-mono text-[10.5px] leading-relaxed text-ash">
          TP {result.true_positives} · FP {result.false_positives} · FN{" "}
          {result.false_negatives} · {result.runtime_ms} ms · ran:{" "}
          {result.meta.tools_ran.join(", ") || "none"}
          {Object.keys(result.meta.tools_not_ran).length > 0
            ? ` · not run: ${Object.keys(result.meta.tools_not_ran).join(", ")}`
            : ""}
        </p>
      ) : null}
    </div>
  );
}
