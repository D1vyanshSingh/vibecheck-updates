import Link from "next/link";
import { redirect } from "next/navigation";

import { CreateWorkspaceForm } from "@/components/app/CreateWorkspaceForm";
import { PageHeader } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "Workspaces" };

export default async function WorkspacesPage() {
  const { memberships } = await requireSession();

  return (
    <div className="max-w-3xl">
      <PageHeader
        eyebrow="Workspaces"
        title="Where assessments live"
        description="Every project, scan, finding and report belongs to exactly one workspace. Row-level security scopes all reads to your membership."
      />

      {memberships.length > 0 ? (
        <section className="mb-8">
          <h2 className="mono mb-3 text-ash">Your memberships</h2>
          <ul className="panel divide-y divide-hairline">
            {memberships.map(({ workspace, role }) => (
              <li
                key={workspace.id}
                className="flex items-center justify-between px-4 py-3"
              >
                <div>
                  <p className="text-[14px] text-fog">{workspace.name}</p>
                  <p className="font-mono text-[10.5px] text-ash">
                    {workspace.kind} · {workspace.slug}
                  </p>
                </div>
                <span className="chip chip-dev">{role}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 font-mono text-[10.5px] text-ash">
            Switch the active workspace from the selector in the sidebar.
          </p>
        </section>
      ) : null}

      <section className="panel p-6">
        <h2 className="display-sub mb-1 text-fog">Create another workspace</h2>
        <p className="body-copy mb-5 text-[13px]">
          Use an agency workspace per client when reports must not share membership
          with your own projects.
        </p>
        <CreateWorkspaceForm />
      </section>

      <p className="mt-6 font-mono text-[10.5px] text-ash">
        Need to join an existing workspace?{" "}
        <Link href="/app/settings" className="text-lavender hover:underline">
          Open the invitation link
        </Link>{" "}
        your admin sent you.
      </p>
    </div>
  );
}
