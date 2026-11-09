import Link from "next/link";

import { EmptyState, PageHeader, Pill, SetupNotice, SeverityDot } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Remediation" };

type Row = {
  id: string;
  title: string;
  severity: string;
  status: string;
  remediation: string | null;
  updated_at: string;
};

export default async function RemediationPage() {
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("findings")
    .select("id, title, severity, status, remediation, updated_at")
    .eq("workspace_id", workspace.id)
    .in("status", ["fix_proposed", "fixed", "ready_for_verification", "still_present"])
    .order("updated_at", { ascending: false })
    .limit(200);

  const rows = (data ?? []) as unknown as Row[];

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="Remediation"
        title="Fixes in progress"
        description="Guidance is stored per finding when the analysis produced it. Nothing here is applied, committed or deployed by VibeCheck."
        actions={
          <Link href="/app/findings" className="btn btn-outline h-9 px-3">
            All findings
          </Link>
        }
      />

      {error ? (
        <SetupNotice detail={error.message} />
      ) : rows.length === 0 ? (
        <EmptyState
          title="No finding is in a remediation state"
          body="A finding appears here once it is triaged to fix proposed, fixed or awaiting verification. Status changes are recorded with a timestamp and actor."
        />
      ) : (
        <ul className="panel divide-y divide-hairline">
          {rows.map((row) => (
            <li key={row.id} className="px-4 py-3">
              <div className="flex items-start justify-between gap-3">
                <Link
                  href={`/app/findings/${row.id}`}
                  className="flex items-start gap-2 text-[13.5px] text-fog hover:text-lavender"
                >
                  <span className="mt-1.5">
                    <SeverityDot severity={row.severity} />
                  </span>
                  {row.title}
                </Link>
                <Pill>{row.status.replace(/_/g, " ")}</Pill>
              </div>
              {row.remediation ? (
                <p className="mt-2 max-w-2xl font-mono text-[10.5px] leading-relaxed text-ash">
                  {row.remediation.slice(0, 240)}
                  {row.remediation.length > 240 ? "…" : ""}
                </p>
              ) : (
                <p className="mt-2 font-mono text-[10.5px] text-ash">
                  No guidance stored for this finding yet.
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
