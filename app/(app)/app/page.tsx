import Link from "next/link";

import {
  EmptyState,
  InlineLink,
  PageHeader,
  Pill,
  SetupNotice,
  SeverityDot,
  StatCard,
} from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Overview" };

type ScanRow = {
  id: string;
  status: string;
  created_at: string;
  findings_total: number | null;
  projects: { name: string } | { name: string }[] | null;
};

type FindingRow = {
  id: string;
  severity: string;
  title: string;
  status: string;
  project_id: string;
  created_at: string;
};

export default async function DashboardPage() {
  const { supabase, workspace, role } = await requireSession();
  if (!workspace) return null;

  const ws = workspace.id;

  const [projectsRes, scansRes, runningRes, reportsRes, openRes] =
    await Promise.all([
      supabase
        .from("projects")
        .select("id", { count: "exact", head: true })
        .eq("workspace_id", ws),
      supabase
        .from("scans")
        .select("id", { count: "exact", head: true })
        .eq("workspace_id", ws),
      supabase
        .from("scans")
        .select("id", { count: "exact", head: true })
        .eq("workspace_id", ws)
        .in("status", ["queued", "running"]),
      supabase
        .from("reports")
        .select("id", { count: "exact", head: true })
        .eq("workspace_id", ws),
      supabase
        .from("findings")
        .select("id", { count: "exact", head: true })
        .eq("workspace_id", ws)
        .in("status", [
          "open",
          "triaged",
          "under_review",
          "ready_for_verification",
          "still_present",
        ]),
    ]);

  const projects = { total: projectsRes.count ?? 0 };
  const scans = { total: scansRes.count ?? 0 };
  const running = { total: runningRes.count ?? 0 };
  const reports = { total: reportsRes.count ?? 0 };
  const openFindings = { total: openRes.count ?? 0 };

  const schemaMissing = Boolean(
    projectsRes.error ?? scansRes.error ?? reportsRes.error ?? openRes.error,
  );

  if (schemaMissing) {
    return (
      <div>
        <PageHeader
          eyebrow="Overview"
          title={workspace.name}
          description="Live workspace data. Nothing on this page is generated or estimated."
        />
        <SetupNotice detail={projectsRes.error?.message ?? scansRes.error?.message} />
      </div>
    );
  }

  const [{ data: recentScans }, { data: topFindings }, { data: severityRows }] =
    await Promise.all([
      supabase
        .from("scans")
        .select("id, status, created_at, findings_total, projects(name)")
        .eq("workspace_id", workspace.id)
        .order("created_at", { ascending: false })
        .limit(5),
      supabase
        .from("findings")
        .select("id, severity, title, status, project_id, created_at")
        .eq("workspace_id", workspace.id)
        .in("status", ["open", "triaged", "under_review", "still_present"])
        .order("created_at", { ascending: false })
        .limit(6),
      supabase
        .from("findings")
        .select("severity")
        .eq("workspace_id", workspace.id)
        .in("status", ["open", "triaged", "under_review", "still_present"]),
    ]);

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const row of (severityRows ?? []) as Array<{ severity: keyof typeof severityCounts }>) {
    if (row.severity in severityCounts) severityCounts[row.severity] += 1;
  }

  const scansRows = (recentScans ?? []) as unknown as ScanRow[];
  const findingRows = (topFindings ?? []) as unknown as FindingRow[];

  return (
    <div>
      <PageHeader
        eyebrow={`${workspace.kind} workspace · ${role ?? "member"}`}
        title={workspace.name}
        description="Everything below is read from your workspace with row-level security. Empty states mean nothing has been stored yet — not zero risk."
        actions={
          <>
            <Link href="/app/projects/new" className="btn btn-primary h-9 px-3">
              New project
            </Link>
            <Link href="/app/reports" className="btn btn-outline h-9 px-3">
              Reports
            </Link>
          </>
        }
      />

      <section className="mb-7 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Projects" value={projects.total} />
        <StatCard label="Assessments" value={scans.total} hint={`${running.total} in flight`} />
        <StatCard
          label="Open findings"
          value={openFindings.total}
          hint={`${severityCounts.critical} critical · ${severityCounts.high} high`}
          tone={severityCounts.critical > 0 ? "warn" : "default"}
        />
        <StatCard label="Reports" value={reports.total} tone="accent" />
      </section>

      <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
        <section>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="mono text-ash">Recent assessments</h2>
            <Link href="/app/scans" className="mono-sm text-lavender hover:text-fog">
              View all
            </Link>
          </div>
          {scansRows.length === 0 ? (
            <EmptyState
              title="No assessment has run yet"
              body="Upload a source archive or point an assessment at a website from inside a project. Results appear here only after a worker stores them."
              action={
                <Link href="/app/projects" className="btn btn-outline h-9 px-3">
                  Open projects
                </Link>
              }
            />
          ) : (
            <ul className="panel divide-y divide-hairline">
              {scansRows.map((scan) => {
                const project = Array.isArray(scan.projects)
                  ? scan.projects[0]
                  : scan.projects;
                return (
                  <li key={scan.id} className="flex items-center justify-between gap-3 px-4 py-3">
                    <div className="min-w-0">
                      <p className="truncate text-[13.5px] text-fog">
                        {project?.name ?? "Project"}
                      </p>
                      <p className="font-mono text-[10.5px] text-ash">
                        {new Date(scan.created_at).toLocaleString()} ·{" "}
                        {scan.findings_total ?? 0} findings
                      </p>
                    </div>
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
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        <section>
          <h2 className="mono mb-3 text-ash">Highest priority open findings</h2>
          {findingRows.length === 0 ? (
            <div className="panel p-5">
              <p className="font-mono text-[11.5px] leading-relaxed text-ash">
                No open findings stored. This is not a clean bill of health: run an
                assessment to produce evidence.
              </p>
            </div>
          ) : (
            <ul className="panel divide-y divide-hairline">
              {findingRows.map((finding) => (
                <li key={finding.id} className="px-4 py-3">
                  <Link
                    href={`/app/findings/${finding.id}`}
                    className="flex items-start gap-2 text-[13px] text-fog hover:text-lavender"
                  >
                    <span className="mt-1.5">
                      <SeverityDot severity={finding.severity} />
                    </span>
                    <span className="min-w-0">
                      <span className="block truncate">{finding.title}</span>
                      <span className="mt-0.5 block font-mono text-[10px] uppercase tracking-[0.14em] text-ash">
                        {finding.severity} · {finding.status}
                      </span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 font-mono text-[10.5px] text-ash">
            Severity is stored per finding. Confidence and verification state are
            shown on the finding page.
          </p>
        </section>
      </div>

      <p className="mt-8 font-mono text-[10.5px] text-ash">
        Need the raw counts?{" "}
        <InlineLink href="/app/scans">Assessment history</InlineLink> lists every
        run with its coverage.
      </p>
    </div>
  );
}
