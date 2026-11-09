import Link from "next/link";

import { EmptyState, PageHeader, SetupNotice } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Application map" };

type Node = {
  id: string;
  kind: string;
  label: string;
  project_id: string;
  evidence_ref: string | null;
};

export default async function ApplicationMapPage() {
  const { supabase, workspace } = await requireSession();
  if (!workspace) return null;

  const { data, error } = await supabase
    .from("application_map_nodes")
    .select("id, kind, label, project_id, evidence_ref")
    .eq("workspace_id", workspace.id)
    .order("kind", { ascending: true })
    .limit(300);

  const nodes = (data ?? []) as unknown as Node[];

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="Application map"
        title="Routes, endpoints and boundaries"
        description="Every relationship shown here carries a provenance reference. Filenames alone are not treated as evidence of a connection."
        actions={
          <Link href="/app/projects" className="btn btn-outline h-9 px-3">
            Choose a project
          </Link>
        }
      />

      {error ? (
        <SetupNotice detail={error.message} />
      ) : nodes.length === 0 ? (
        <EmptyState
          title="No map has been generated"
          body="The map is built from a completed source assessment that records routes, handlers and data access with file references. Run a source assessment first."
        />
      ) : (
        <ul className="panel divide-y divide-hairline">
          {nodes.map((node) => (
            <li key={node.id} className="flex items-center justify-between gap-3 px-4 py-2.5">
              <div>
                <p className="font-mono text-[11.5px] text-fog">{node.label}</p>
                <p className="font-mono text-[10px] text-ash">
                  {node.kind}
                  {node.evidence_ref ? ` · ${node.evidence_ref}` : " · no evidence reference"}
                </p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
