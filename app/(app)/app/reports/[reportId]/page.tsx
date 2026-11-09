import Link from "next/link";
import { notFound } from "next/navigation";

import { PageHeader, Pill, SetupNotice, SeverityDot } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Report" };

type Report = {
  id: string;
  project_id: string;
  scan_id: string | null;
  report_type: string;
  version: number;
  status: string;
  summary: string | null;
  created_at: string;
  projects: { name: string } | { name: string }[] | null;
};

type Finding = {
  id: string;
  title: string;
  severity: string;
  status: string;
  confidence: string;
  file_path: string | null;
  line_start: number | null;
};

export default async function ReportDetailPage({
  params,
}: {
  params: Promise<{ reportId: string }>;
}) {
  const { reportId } = await params;
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("reports")
    .select(
      "id, project_id, scan_id, report_type, version, status, summary, created_at, projects(name)",
    )
    .eq("id", reportId)
    .eq("workspace_id", workspace.id)
    .maybeSingle();

  if (error) return <SetupNotice detail={error.message} />;
  if (!data) notFound();

  const report = data as unknown as Report;
  const project = Array.isArray(report.projects) ? report.projects[0] : report.projects;

  const { data: findingData } = report.scan_id
    ? await supabase
        .from("findings")
        .select("id, title, severity, status, confidence, file_path, line_start")
        .eq("scan_id", report.scan_id)
        .order("severity", { ascending: true })
        .limit(500)
    : { data: [] as Finding[] };

  const findings = (findingData ?? []) as unknown as Finding[];

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow={`${report.report_type.replace(/_/g, " ")} · v${report.version}`}
        title={project?.name ?? "Report"}
        description={`Generated ${new Date(report.created_at).toLocaleString()} from stored assessment data.`}
        actions={
          <Link
            href={report.scan_id ? `/app/scans/${report.scan_id}` : "/app/scans"}
            className="btn btn-outline h-9 px-3"
          >
            Source run
          </Link>
        }
      />

      <div className="mb-5 flex items-center gap-2">
        <Pill tone={report.status === "ready" ? "live" : "warn"}>
          {report.status}
        </Pill>
        <span className="font-mono text-[10.5px] text-ash">
          {findings.length} findings in this snapshot
        </span>
      </div>

      {report.summary ? (
        <section className="panel mb-5 p-5">
          <h2 className="mono mb-2 text-ash">Summary</h2>
          <p className="font-mono text-[12px] leading-relaxed text-muted">
            {report.summary}
          </p>
        </section>
      ) : (
        <section className="panel mb-5 p-5">
          <h2 className="mono mb-2 text-ash">Summary</h2>
          <p className="font-mono text-[11.5px] leading-relaxed text-ash">
            No narrative summary is stored. A summary is only produced when the
            report generator ran with available evidence.
          </p>
        </section>
      )}

      <section>
        <h2 className="mono mb-3 text-ash">Findings in this report</h2>
        {findings.length === 0 ? (
          <div className="panel p-5 font-mono text-[11.5px] text-ash">
            This report snapshot has no findings rows. That may mean a clean run or a
            run whose findings were not persisted — the source run above states
            which.
          </div>
        ) : (
          <ul className="panel divide-y divide-hairline">
            {findings.map((finding) => (
              <li key={finding.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
                <Link
                  href={`/app/findings/${finding.id}`}
                  className="flex items-center gap-2 text-[13px] text-fog hover:text-lavender"
                >
                  <SeverityDot severity={finding.severity} />
                  {finding.title}
                </Link>
                <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ash">
                  {finding.severity} · {finding.confidence}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
