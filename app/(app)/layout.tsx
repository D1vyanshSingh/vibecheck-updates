import { AppShell } from "@/components/app/AppShell";
import { requireSession } from "@/lib/data/context";

export const dynamic = "force-dynamic";

/**
 * Authenticated console shell. Middleware rejects signed-out visitors before
 * this renders; requireSession() is the second check for direct renders.
 */
export default async function AppLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  const { user, memberships, workspace, role } = await requireSession();

  // A signed-in user with no workspace goes straight to workspace creation
  // rather than seeing an empty console.
  const hasWorkspace = memberships.length > 0;

  return (
    <AppShell
      workspaces={memberships.map((m) => ({
        id: m.workspace.id,
        name: m.workspace.name,
        kind: m.workspace.kind,
      }))}
      activeWorkspaceId={workspace?.id ?? null}
      role={role}
      email={user.email ?? "signed in"}
    >
      {hasWorkspace ? children : <NoWorkspace />}
    </AppShell>
  );
}

function NoWorkspace() {
  // Rendered inside the shell so navigation still works.
  return (
    <div className="panel p-7">
      <p className="eyebrow-plain mb-2">Step 1 of 3</p>
      <h1 className="display-sub text-fog">Create your first workspace</h1>
      <p className="body-copy mt-2 max-w-xl text-[13.5px]">
        A workspace owns projects, assessments, findings and reports. Personal
        workspaces are for your own code; agency workspaces are for client
        engagements with separate membership.
      </p>
      <a
        href="/app/workspaces"
        className="btn btn-primary mt-5 inline-flex w-auto"
      >
        Choose a workspace type
      </a>
    </div>
  );
}

export const metadata = { title: "Console" };
