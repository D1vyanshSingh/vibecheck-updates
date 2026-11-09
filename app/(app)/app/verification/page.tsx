import Link from "next/link";

import { EmptyState, PageHeader, Pill, SetupNotice } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Verification" };

type Run = {
  id: string;
  finding_id: string;
  status: string;
  created_at: string;
  completed_at: string | null;
};

export default async function VerificationPage() {
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("verification_runs")
    .select("id, finding_id, status, created_at, completed_at")
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: false })
    .limit(100);

  const runs = (data ?? []) as unknown as Run[];

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="Verification"
        title="Independent re-tests"
        description="A finding moves to verified only when a re-test produced evidence. A status dropdown cannot do that, and the AI cannot mark a finding resolved."
        actions={
          <Link href="/app/findings" className="btn btn-outline h-9 px-3">
            Open findings
          </Link>
        }
      />

      {error ? (
        <SetupNotice detail={error.message} />
      ) : runs.length === 0 ? (
        <EmptyState
          title="No verification has been requested"
          body="Request a re-test from a finding page. The backend queues a verification scan against the latest stored source snapshot for that project."
        />
      ) : (
        <ul className="panel divide-y divide-hairline">
          {runs.map((run) => (
            <li key={run.id} className="flex items-center justify-between gap-3 px-4 py-3">
              <Link
                href={`/app/findings/${run.finding_id}`}
                className="font-mono text-[11.5px] text-fog hover:text-lavender"
              >
                finding {run.finding_id.slice(0, 8)}
              </Link>
              <div className="flex items-center gap-3">
                <span className="font-mono text-[10px] text-ash">
                  {new Date(run.created_at).toLocaleString()}
                </span>
                <Pill
                  tone={
                    run.status === "passed"
                      ? "live"
                      : run.status === "failed"
                        ? "danger"
                        : "warn"
                  }
                >
                  {run.status}
                </Pill>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
