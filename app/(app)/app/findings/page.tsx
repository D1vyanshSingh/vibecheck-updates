import Link from "next/link";

import {
  DataTable,
  EmptyState,
  PageHeader,
  Pill,
  SeverityDot,
  SetupNotice,
  Td,
  Th,
} from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Findings" };

const SEVERITIES = ["critical", "high", "medium", "low", ""] as const;
const OPEN_STATES = [
  "open",
  "triaged",
  "under_review",
  "ready_for_verification",
  "still_present",
] as const;

type FindingRow = {
  id: string;
  severity: string;
  status: string;
  title: string;
  scanner: string;
  confidence: string;
  file_path: string | null;
  line_start: number | null;
  created_at: string;
  projects: { name: string } | { name: string }[] | null;
};

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<{ severity?: string; status?: string; projectId?: string }>;
}) {
  const { severity, status, projectId } = await searchParams;
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  let query = supabase
    .from("findings")
    .select(
      "id, severity, status, title, scanner, confidence, file_path, line_start, created_at, projects(name)",
      { count: "exact" },
    )
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: false })
    .limit(200);

  if (severity && SEVERITIES.includes(severity as (typeof SEVERITIES)[number])) {
    query = query.eq("severity", severity);
  }
  if (status) query = query.eq("status", status);
  if (projectId) query = query.eq("project_id", projectId);

  const { data, error, count } = await query;
  const findings = (data ?? []) as unknown as FindingRow[];

  const buildHref = (nextSeverity: string) => {
    const params = new URLSearchParams();
    if (nextSeverity) params.set("severity", nextSeverity);
    if (status) params.set("status", status);
    if (projectId) params.set("projectId", projectId);
    const qs = params.toString();
    return `/app/findings${qs ? `?${qs}` : ""}`;
  };

  return (
    <div>
      <PageHeader
        eyebrow="Findings"
        title="Stored findings"
        description="One row per normalized scanner finding. Severity is stored; confidence and verification state live on the finding page so the two are never conflated."
        actions={
          <Link
            href={status ? `/app/findings?severity=${severity ?? ""}` : `/app/findings?status=open`}
            className="btn btn-outline h-9 px-3"
          >
            {status ? "Show all states" : "Show open only"}
          </Link>
        }
      />

      <nav aria-label="Severity filter" className="mb-5 flex flex-wrap gap-2">
        <Link
          href={buildHref("")}
          className={`mono-sm border px-2.5 py-1.5 ${
            !severity ? "border-lavender/50 text-lavender" : "border-hairline text-ash hover:text-fog"
          }`}
        >
          All
        </Link>
        {SEVERITIES.filter(Boolean).map((level) => (
          <Link
            key={level}
            href={buildHref(level)}
            className={`mono-sm border px-2.5 py-1.5 ${
              severity === level
                ? "border-lavender/50 text-lavender"
                : "border-hairline text-ash hover:text-fog"
            }`}
          >
            {level}
          </Link>
        ))}
      </nav>

      {error ? (
        <SetupNotice detail={error.message} />
      ) : findings.length === 0 ? (
        <EmptyState
          title="No findings match this view"
          body={
            severity || status
              ? "Relax the filter. An empty filtered list does not mean the application is clean."
              : "No scan has stored findings in this workspace yet. Run an assessment from a project to produce evidence."
          }
          action={
            <Link href="/app/projects" className="btn btn-outline h-9 px-3">
              Open projects
            </Link>
          }
        />
      ) : (
        <>
          <DataTable
            head={
              <>
                <Th>Finding</Th>
                <Th>Severity</Th>
                <Th>State</Th>
                <Th>Scanner</Th>
                <Th>Location</Th>
                <Th />
              </>
            }
          >
            {findings.map((finding) => {
              const project = Array.isArray(finding.projects)
                ? finding.projects[0]
                : finding.projects;
              return (
                <tr key={finding.id} className="hover:bg-white/[0.02]">
                  <Td>
                    <Link
                      href={`/app/findings/${finding.id}`}
                      className="text-[13.5px] text-fog hover:text-lavender"
                    >
                      {finding.title}
                    </Link>
                    <span className="mt-0.5 block font-mono text-[10px] text-ash">
                      {project?.name ?? "Project"} · {finding.confidence} confidence
                    </span>
                  </Td>
                  <Td>
                    <span className="flex items-center gap-1.5 font-mono text-[10.5px] uppercase tracking-[0.12em]">
                      <SeverityDot severity={finding.severity} />
                      {finding.severity}
                    </span>
                  </Td>
                  <Td>
                    <Pill>{finding.status.replace(/_/g, " ")}</Pill>
                  </Td>
                  <Td>
                    <span className="font-mono text-[10.5px]">{finding.scanner}</span>
                  </Td>
                  <Td>
                    <span className="font-mono text-[10.5px]">
                      {finding.file_path
                        ? `${finding.file_path}${finding.line_start ? `:${finding.line_start}` : ""}`
                        : "—"}
                    </span>
                  </Td>
                  <Td className="text-right">
                    <Link
                      href={`/app/findings/${finding.id}`}
                      className="mono-sm text-lavender hover:text-fog"
                    >
                      Open
                    </Link>
                  </Td>
                </tr>
              );
            })}
          </DataTable>
          <p className="mt-3 font-mono text-[10.5px] text-ash">
            {count ?? findings.length} matching rows
            {OPEN_STATES.length ? " · open-state filter available above" : ""}
          </p>
        </>
      )}
    </div>
  );
}
