import Link from "next/link";

import { NewProjectForm } from "@/components/app/NewProjectForm";
import { PageHeader } from "@/components/app/ui";
import { requireSession } from "@/lib/data/context";

export const metadata = { title: "New project" };

export default async function NewProjectPage() {
  const { workspace, role } = await requireSession();

  if (!workspace) {
    return (
      <div className="panel max-w-xl p-7">
        <h1 className="display-sub text-fog">Create a workspace first</h1>
        <p className="body-copy mt-2 text-[13.5px]">
          Projects belong to a workspace, and a workspace needs an owner.
        </p>
        <Link href="/app/workspaces" className="btn btn-primary mt-4 inline-flex w-auto">
          Create workspace
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-2xl">
      <PageHeader
        eyebrow={`${workspace.name} · ${role ?? "member"}`}
        title="New project"
        description="Only the fields the assessment engine actually uses are collected. Everything else can be added later."
      />
      <div className="panel p-6">
        <NewProjectForm />
      </div>
    </div>
  );
}
