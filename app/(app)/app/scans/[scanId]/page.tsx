import Link from "next/link";
import { notFound } from "next/navigation";

import { ReportActions } from "@/components/app/ReportActions";
import { ScanAnalysisPanel } from "@/components/app/ScanAnalysisPanel";
import { PageHeader, Pill, SetupNotice } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Assessment" };

type Scan = {
  id: string;
  project_id: string;
  status: string;
  trigger: string;
  findings_total: number | null;
  error_message: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  coverage: Record<string, unknown> | null;
  projects: { name: string } | { name: string }[] | null;
};

type Job = {
  id: string;
  kind: string;
  status: string;
  attempts: number | null;
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
};

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("scans")
    .select(
      "id, project_id, status, trigger, findings_total, error_message, created_at, started_at, completed_at, coverage, projects(name)",
    )
    .eq("id", scanId)
    .eq("workspace_id", workspace.id)
    .maybeSingle();

  if (error) return <SetupNotice detail={error.message} />;
  if (!data) notFound();

  const scan = data as unknown as Scan;
  const project = Array.isArray(scan.projects) ? scan.projects[0] : scan.projects;

  const { data: jobData } = await supabase
    .from("scan_jobs")
    .select("id, kind, status, attempts, error_message, started_at, finished_at")
    .eq("scan_id", scan.id)
    .order("kind", { ascending: true });

  const jobs = (jobData ?? []) as unknown as Job[];

  const coverage = scan.coverage as
    | { scanners?: Record<string, { status?: string; detail?: string }> }
    | null;

  return (
    <div>
      <PageHeader
        eyebrow={`Run ${scan.id.slice(0, 8)} · ${scan.trigger}`}
        title={project?.name ?? "Assessment"}
        description={`Queued ${new Date(scan.created_at).toLocaleString()}. Findings: ${
          scan.findings_total ?? 0
        }.`}
        actions={
          <Link
            href={`/app/findings?projectId=${scan.project_id}`}
            className="btn btn-outline h-9 px-3"
          >
            Findings for this project
          </Link>
        }
      />

      <div className="mb-6 flex flex-wrap items-center gap-3">
        <Pill
          tone={
            scan.status === "completed"
              ? "live"
              : scan.status === "failed"
                ? "danger"
                : "warn"
          }
        >
          {scan.status}
        </Pill>
        {scan.started_at ? (
          <span className="font-mono text-[10.5px] text-ash">
            started {new Date(scan.started_at).toLocaleTimeString()}
          </span>
        ) : null}
        {scan.completed_at ? (
          <span className="font-mono text-[10.5px] text-ash">
            finished {new Date(scan.completed_at).toLocaleTimeString()}
          </span>
        ) : null}
      </div>

      {scan.error_message ? (
        <div className="mb-6 border border-red-500/30 bg-red-500/10 p-4">
          <p className="mono-sm text-red-300">Run error</p>
          <p className="mt-1 font-mono text-[11.5px] leading-relaxed text-red-200">
            {scan.error_message}
          </p>
        </div>
      ) : null}

      <div className="grid gap-5 lg:grid-cols-2">
        <section>
          <h2 className="mono mb-3 text-ash">Jobs</h2>
          {jobs.length === 0 ? (
            <div className="panel p-5 font-mono text-[11.5px] text-ash">
              No job rows were stored for this run. The scan may have been rejected
              before dispatch.
            </div>
          ) : (
            <ul className="panel divide-y divide-hairline">
              {jobs.map((job) => (
                <li key={job.id} className="px-4 py-3">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-mono text-[11.5px] text-fog">{job.kind}</span>
                    <Pill
                      tone={
                        job.status === "completed"
                          ? "live"
                          : job.status === "failed"
                            ? "danger"
                            : "muted"
                      }
                    >
                      {job.status}
                    </Pill>
                  </div>
                  {job.error_message ? (
                    <p className="mt-1 font-mono text-[10.5px] text-red-300">
                      {job.error_message}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h2 className="mono mb-3 text-ash">Coverage</h2>
          {!coverage?.scanners ? (
            <div className="panel p-5 font-mono text-[11.5px] leading-relaxed text-ash">
              No coverage record stored. An absent coverage record means the run did
              not report which checks executed — treat the result as incomplete.
            </div>
          ) : (
            <ul className="panel divide-y divide-hairline">
              {Object.entries(coverage.scanners).map(([name, info]) => (
                <li key={name} className="flex items-start justify-between gap-3 px-4 py-2.5">
                  <div>
                    <p className="font-mono text-[11.5px] text-fog">{name}</p>
                    {info?.detail ? (
                      <p className="mt-0.5 font-mono text-[10px] text-ash">
                        {info.detail}
                      </p>
                    ) : null}
                  </div>
                  <Pill
                    tone={
                      info?.status === "ran"
                        ? "live"
                        : info?.status === "failed"
                          ? "danger"
                          : "muted"
                    }
                  >
                    {info?.status ?? "unknown"}
                  </Pill>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <ScanAnalysisPanel scanId={scan.id} />
        <ReportActions scanId={scan.id} />
      </div>
    </div>
  );
}
