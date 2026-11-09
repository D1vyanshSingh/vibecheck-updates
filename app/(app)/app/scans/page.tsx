import Link from "next/link";

import {
  DataTable,
  EmptyState,
  PageHeader,
  Pill,
  SetupNotice,
  Td,
  Th,
} from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Assessments" };

type ScanRow = {
  id: string;
  status: string;
  trigger: string;
  created_at: string;
  completed_at: string | null;
  findings_total: number | null;
  error_message: string | null;
  coverage: Record<string, unknown> | null;
  projects: { id: string; name: string } | { id: string; name: string }[] | null;
};

const statusTone = (status: string) =>
  status === "completed"
    ? "live"
    : status === "failed"
      ? "danger"
      : status === "cancelled"
        ? "muted"
        : "warn";

export default async function ScansPage() {
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("scans")
    .select(
      "id, status, trigger, created_at, completed_at, findings_total, error_message, coverage, projects(id, name)",
    )
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: false })
    .limit(100);

  const scans = (data ?? []) as unknown as ScanRow[];

  return (
    <div>
      <PageHeader
        eyebrow="Assessments"
        title="Assessment history"
        description="Every row is a real queued, running or finished run. A run with no findings is not the same as a secure application — open a run to see which checks actually executed."
      />

      {error ? (
        <SetupNotice detail={error.message} />
      ) : scans.length === 0 ? (
        <EmptyState
          title="No assessments have been queued"
          body="Open a project and add a source — a website URL, a repository or a ZIP archive. The run appears here as soon as the backend accepts it."
          action={
            <Link href="/app/projects" className="btn btn-outline h-9 px-3">
              Go to projects
            </Link>
          }
        />
      ) : (
        <DataTable
          head={
            <>
              <Th>Project</Th>
              <Th>Status</Th>
              <Th>Trigger</Th>
              <Th>Findings</Th>
              <Th>Started</Th>
              <Th />
            </>
          }
        >
          {scans.map((scan) => {
            const project = Array.isArray(scan.projects)
              ? scan.projects[0]
              : scan.projects;
            return (
              <tr key={scan.id} className="hover:bg-white/[0.02]">
                <Td>
                  <Link
                    href={`/app/scans/${scan.id}`}
                    className="text-[13.5px] text-fog hover:text-lavender"
                  >
                    {project?.name ?? "Project"}
                  </Link>
                  <span className="mt-0.5 block font-mono text-[10px] text-ash">
                    {scan.id.slice(0, 8)}
                  </span>
                </Td>
                <Td>
                  <Pill tone={statusTone(scan.status)}>{scan.status}</Pill>
                </Td>
                <Td>
                  <span className="font-mono text-[10.5px] text-ash">
                    {scan.trigger}
                  </span>
                </Td>
                <Td>
                  <span className="font-mono text-[11px]">
                    {scan.findings_total ?? 0}
                  </span>
                </Td>
                <Td>
                  <span className="font-mono text-[10.5px]">
                    {new Date(scan.created_at).toLocaleString()}
                  </span>
                </Td>
                <Td className="text-right">
                  <Link
                    href={`/app/scans/${scan.id}`}
                    className="mono-sm text-lavender hover:text-fog"
                  >
                    Open
                  </Link>
                </Td>
              </tr>
            );
          })}
        </DataTable>
      )}
    </div>
  );
}
