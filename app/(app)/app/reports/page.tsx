import Link from "next/link";

import { EmptyState, PageHeader, Pill, SetupNotice } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Reports" };

type Report = {
  id: string;
  report_type: string;
  version: number;
  status: string;
  created_at: string;
  scan_id: string | null;
  projects: { name: string } | { name: string }[] | null;
};

export default async function ReportsPage() {
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("reports")
    .select("id, report_type, version, status, created_at, scan_id, projects(name)")
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: false })
    .limit(100);

  const reports = (data ?? []) as unknown as Report[];

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="Reports"
        title="Stored assessments"
        description="Two report types are produced from the same assessment data: a client security report and a technical assessment. Every version is reproducible from persisted evidence."
        actions={
          <Link href="/app/scans" className="btn btn-outline h-9 px-3">
            Assessment history
          </Link>
        }
      />

      {error ? (
        <SetupNotice detail={error.message} />
      ) : reports.length === 0 ? (
        <EmptyState
          title="No report has been generated"
          body="Reports are generated from a completed scan with stored findings. Generate one from a scan page once a run has finished."
        />
      ) : (
        <ul className="panel divide-y divide-hairline">
          {reports.map((report) => {
            const project = Array.isArray(report.projects)
              ? report.projects[0]
              : report.projects;
            return (
              <li key={report.id} className="flex items-center justify-between gap-3 px-4 py-3">
                <div>
                  <p className="text-[13.5px] text-fog">
                    {project?.name ?? "Project"} ·{" "}
                    {report.report_type.replace(/_/g, " ")} v{report.version}
                  </p>
                  <p className="mt-0.5 font-mono text-[10px] text-ash">
                    {new Date(report.created_at).toLocaleString()}
                    {report.scan_id ? ` · scan ${report.scan_id.slice(0, 8)}` : ""}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <Pill tone={report.status === "ready" ? "live" : "warn"}>
                    {report.status}
                  </Pill>
                  <Link
                    href={`/app/reports/${report.id}`}
                    className="mono-sm text-lavender hover:text-fog"
                  >
                    Open
                  </Link>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
