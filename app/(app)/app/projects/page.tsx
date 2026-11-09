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

export const metadata = { title: "Projects" };

type ProjectRow = {
  id: string;
  name: string;
  description: string | null;
  project_type: string;
  website_url: string | null;
  repository_url: string | null;
  created_at: string;
};

export default async function ProjectsPage() {
  const { supabase, workspace, role } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("projects")
    .select(
      "id, name, description, project_type, website_url, repository_url, created_at",
    )
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: false });

  const projects = (data ?? []) as unknown as ProjectRow[];

  return (
    <div>
      <PageHeader
        eyebrow="Projects"
        title="Applications under assessment"
        description="A project groups the sources, assessments, findings and reports for one application. Multiple sources (URL, GitHub, ZIP) can belong to the same project."
        actions={
          <Link href="/app/projects/new" className="btn btn-primary h-9 px-3">
            New project
          </Link>
        }
      />

      {error ? (
        <SetupNotice detail={error.message} />
      ) : projects.length === 0 ? (
        <EmptyState
          title="No projects in this workspace"
          body="Create a project to hold assessment sources and history. Nothing is created automatically, so an empty list is expected on a fresh workspace."
          action={
            <Link href="/app/projects/new" className="btn btn-outline h-9 px-3">
              Create the first project
            </Link>
          }
        />
      ) : (
        <DataTable
          head={
            <>
              <Th>Project</Th>
              <Th>Type</Th>
              <Th>Sources</Th>
              <Th>Created</Th>
              <Th />
            </>
          }
        >
          {projects.map((project) => (
            <tr key={project.id} className="hover:bg-white/[0.02]">
              <Td>
                <Link
                  href={`/app/projects/${project.id}`}
                  className="text-[13.5px] text-fog hover:text-lavender"
                >
                  {project.name}
                </Link>
                {project.description ? (
                  <span className="mt-0.5 block max-w-md truncate font-mono text-[10.5px] text-ash">
                    {project.description}
                  </span>
                ) : null}
              </Td>
              <Td>
                <Pill>{project.project_type.replace(/_/g, " ")}</Pill>
              </Td>
              <Td>
                <span className="font-mono text-[10.5px] text-ash">
                  {project.website_url ? "URL " : ""}
                  {project.repository_url ? "repo" : ""}
                  {!project.website_url && !project.repository_url ? "—" : ""}
                </span>
              </Td>
              <Td>
                <span className="font-mono text-[10.5px]">
                  {new Date(project.created_at).toLocaleDateString()}
                </span>
              </Td>
              <Td className="text-right">
                <Link
                  href={`/app/projects/${project.id}`}
                  className="mono-sm text-lavender hover:text-fog"
                >
                  Open
                </Link>
              </Td>
            </tr>
          ))}
        </DataTable>
      )}

      <p className="mt-4 font-mono text-[10.5px] text-ash">
        Your role: {role ?? "none"}. Only owners and admins can delete a project.
      </p>
    </div>
  );
}
