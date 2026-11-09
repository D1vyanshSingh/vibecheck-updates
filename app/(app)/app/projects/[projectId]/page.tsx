import Link from "next/link";
import { notFound } from "next/navigation";

import { AssessmentSourceForm } from "@/components/app/AssessmentSourceForm";
import { UrlAssessmentForm } from "@/components/app/UrlAssessmentForm";
import {
  EmptyState,
  PageHeader,
  Pill,
  SetupNotice,
} from "@/components/app/ui";
import { can, requireSession } from "@/lib/data/context";

export const metadata = { title: "Project" };

type Project = {
  id: string;
  name: string;
  description: string | null;
  project_type: string;
  website_url: string | null;
  repository_url: string | null;
  created_at: string;
};

type ScanRow = {
  id: string;
  status: string;
  created_at: string;
  findings_total: number | null;
};

export default async function ProjectDetailPage({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  const { supabase, workspace, role } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("projects")
    .select(
      "id, name, description, project_type, website_url, repository_url, created_at",
    )
    .eq("id", projectId)
    .eq("workspace_id", workspace.id)
    .maybeSingle();

  if (error) {
    return <SetupNotice detail={error.message} />;
  }
  if (!data) notFound();

  const project = data as unknown as Project;

  const { data: scanData } = await supabase
    .from("scans")
    .select("id, status, created_at, findings_total")
    .eq("project_id", project.id)
    .order("created_at", { ascending: false })
    .limit(10);

  const scans = (scanData ?? []) as unknown as ScanRow[];

  return (
    <div>
      <PageHeader
        eyebrow={project.project_type.replace(/_/g, " ")}
        title={project.name}
        description={
          project.description ??
          "No description stored for this project yet."
        }
        actions={
          <Link href="/app/findings" className="btn btn-outline h-9 px-3">
            Findings
          </Link>
        }
      />

      <div className="grid gap-5 lg:grid-cols-[1.15fr_1fr]">
        <div className="space-y-5">
          {can(role, "developer") ? (
            <>
              <AssessmentSourceForm
                workspaceId={workspace.id}
                projectId={project.id}
              />
              <UrlAssessmentForm
                workspaceId={workspace.id}
                projectId={project.id}
                defaultUrl={project.website_url}
              />
            </>
          ) : (
            <div className="panel p-5">
              <p className="mono-sm text-ash">Read-only role</p>
              <p className="body-copy mt-2 text-[13px]">
                Your role can view assessments but not start them. Ask an owner or
                admin for developer access.
              </p>
            </div>
          )}

          <section>
            <h2 className="mono mb-3 text-ash">Assessment history</h2>
            {scans.length === 0 ? (
              <EmptyState
                title="This project has not been assessed"
                body="Upload a source archive above. Only runs that the backend actually accepted appear in this list."
              />
            ) : (
              <ul className="panel divide-y divide-hairline">
                {scans.map((scan) => (
                  <li
                    key={scan.id}
                    className="flex items-center justify-between gap-3 px-4 py-3"
                  >
                    <Link
                      href={`/app/scans/${scan.id}`}
                      className="font-mono text-[11.5px] text-fog hover:text-lavender"
                    >
                      {scan.id.slice(0, 8)}
                      <span className="ml-3 text-ash">
                        {new Date(scan.created_at).toLocaleString()}
                      </span>
                    </Link>
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-[10.5px] text-ash">
                        {scan.findings_total ?? 0} findings
                      </span>
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
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        <aside className="space-y-4">
          <section className="panel p-5">
            <h2 className="mono mb-3 text-ash">Target</h2>
            <dl className="space-y-2 font-mono text-[11.5px]">
              <div className="flex justify-between gap-4">
                <dt className="text-ash">Type</dt>
                <dd className="text-muted">{project.project_type.replace(/_/g, " ")}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-ash">Website</dt>
                <dd className="truncate text-muted">
                  {project.website_url ?? "not set"}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-ash">Repository</dt>
                <dd className="truncate text-muted">
                  {project.repository_url ?? "not set"}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-ash">Created</dt>
                <dd className="text-muted">
                  {new Date(project.created_at).toLocaleDateString()}
                </dd>
              </div>
            </dl>
          </section>

          <section className="panel p-5">
            <h2 className="mono mb-2 text-ash">What runs</h2>
            <p className="font-mono text-[11px] leading-relaxed text-ash">
              Source assessments run the allowlisted scanner registry (Semgrep,
              Gitleaks, OSV-Scanner and the built-in checks). The run page lists
              exactly which tools executed, which were skipped and why.
            </p>
          </section>
        </aside>
      </div>
    </div>
  );
}
