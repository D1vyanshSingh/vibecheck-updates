import Link from "next/link";

import { RunBenchmarkButton } from "@/components/app/RunBenchmarkButton";
import { EmptyState, PageHeader, Pill, SetupNotice } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Benchmarks" };

type Run = {
  id: string;
  corpus_version: string;
  scanner: string;
  true_positives: number;
  false_positives: number;
  false_negatives: number;
  created_at: string;
};

export default async function BenchmarksPage() {
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("benchmark_runs")
    .select(
      "id, corpus_version, scanner, true_positives, false_positives, false_negatives, created_at",
    )
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: false })
    .limit(100);

  const runs = (data ?? []) as unknown as Run[];

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="Benchmarks"
        title="Detection quality on synthetic fixtures"
        description="Scores are only meaningful with a stated corpus version and sample size. No number on this page is estimated."
        actions={
          <>
            <RunBenchmarkButton workspaceId={workspace.id} />
            <Link href="/app/findings" className="btn btn-outline h-9 px-3">
              Real findings
            </Link>
          </>
        }
      />

      {error ? (
        <SetupNotice detail={error.message} />
      ) : runs.length === 0 ? (
        <EmptyState
          title="No benchmark has been recorded"
          body="Run the corpus to score the scanners installed on this worker. The run is only stored after the scanners actually executed against the fixture tree."
        />
      ) : (
        <div className="panel overflow-hidden">
          <table className="w-full border-collapse text-left">
            <thead className="border-b border-hairline bg-elevated/40">
              <tr className="mono-sm text-ash">
                <th className="px-4 py-2.5 font-normal">Scanner</th>
                <th className="px-4 py-2.5 font-normal">Corpus</th>
                <th className="px-4 py-2.5 font-normal">TP</th>
                <th className="px-4 py-2.5 font-normal">FP</th>
                <th className="px-4 py-2.5 font-normal">FN</th>
                <th className="px-4 py-2.5 font-normal">Ran</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline/60">
              {runs.map((run) => (
                <tr key={run.id}>
                  <td className="px-4 py-3 font-mono text-[11.5px] text-fog">
                    {run.scanner}
                  </td>
                  <td className="px-4 py-3 font-mono text-[10.5px] text-ash">
                    <Pill>{run.corpus_version}</Pill>
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px] text-muted">
                    {run.true_positives}
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px] text-muted">
                    {run.false_positives}
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px] text-muted">
                    {run.false_negatives}
                  </td>
                  <td className="px-4 py-3 font-mono text-[10.5px] text-ash">
                    {new Date(run.created_at).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
