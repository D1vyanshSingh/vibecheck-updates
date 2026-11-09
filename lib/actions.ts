"use server";

import { revalidatePath } from "next/cache";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { z } from "zod";

import {
  ROLE_RANK,
  WORKSPACE_COOKIE,
  requireSession,
  requireRole,
  can,
  type Role,
} from "@/lib/data/context";
import { getSupabaseServerClient } from "@/lib/supabase/server";

const slugify = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48) || "workspace";

export type ActionResult = { ok: boolean; message?: string };

/* ------------------------------------------------------------------ auth */

export async function signOutAction() {
  const supabase = await getSupabaseServerClient();
  await supabase.auth.signOut();
  const store = await cookies();
  store.delete(WORKSPACE_COOKIE);
  redirect("/login");
}

/* ------------------------------------------------------------ workspaces */

const workspaceSchema = z.object({
  name: z.string().trim().min(2).max(80),
  kind: z.enum(["personal", "agency"]),
});

export async function createWorkspaceAction(
  _prev: ActionResult | null,
  formData: FormData,
): Promise<ActionResult> {
  const parsed = workspaceSchema.safeParse({
    name: formData.get("name"),
    kind: formData.get("kind") ?? "personal",
  });
  if (!parsed.success) {
    return { ok: false, message: "Give the workspace a name (2–80 characters)." };
  }

  const { supabase } = await requireSession();

  // create_workspace() inserts the workspace and the owner membership in one
  // transaction under security definer rights, so a half-created workspace is
  // impossible.
  const { data, error } = await supabase.rpc("create_workspace", {
    p_name: parsed.data.name,
    p_kind: parsed.data.kind,
    p_slug: slugify(parsed.data.name),
  });

  if (error) {
    return { ok: false, message: error.message };
  }

  const workspaceId =
    typeof data === "string"
      ? data
      : (data as { id?: string } | null)?.id ?? null;

  if (!workspaceId) {
    return { ok: false, message: "Workspace was created but no id was returned." };
  }

  const store = await cookies();
  store.set(WORKSPACE_COOKIE, workspaceId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });

  revalidatePath("/app", "layout");
  return { ok: true };
}

export async function switchWorkspaceAction(formData: FormData): Promise<void> {
  const workspaceId = String(formData.get("workspace_id") ?? "");
  const { memberships } = await requireSession();

  if (!memberships.some((m) => m.workspace.id === workspaceId)) {
    return;
  }

  const store = await cookies();
  store.set(WORKSPACE_COOKIE, workspaceId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });

  revalidatePath("/app", "layout");
}

/* -------------------------------------------------------------- projects */

const projectSchema = z.object({
  name: z.string().trim().min(2).max(120),
  description: z.string().trim().max(2000).optional().default(""),
  project_type: z
    .enum(["web_app", "api", "full_stack", "static_site", "mobile_backend"])
    .default("web_app"),
  website_url: z
    .union([z.string().url(), z.literal("")])
    .optional()
    .default(""),
  repository_url: z
    .union([z.string().url(), z.literal("")])
    .optional()
    .default(""),
});

export async function createProjectAction(
  _prev: ActionResult | null,
  formData: FormData,
): Promise<ActionResult> {
  const parsed = projectSchema.safeParse({
    name: formData.get("name"),
    description: formData.get("description") ?? "",
    project_type: formData.get("project_type") ?? "web_app",
    website_url: formData.get("website_url") ?? "",
    repository_url: formData.get("repository_url") ?? "",
  });

  if (!parsed.success) {
    return {
      ok: false,
      message: "Check the project name and that any URLs start with https://.",
    };
  }

  const { supabase, workspace, role } = await requireSession();
  if (!workspace) return { ok: false, message: "Create a workspace first." };
  if (!can(role, "developer")) {
    return { ok: false, message: "Viewers cannot create projects." };
  }

  const { data, error } = await supabase
    .from("projects")
    .insert({
      workspace_id: workspace.id,
      name: parsed.data.name,
      description: parsed.data.description || null,
      project_type: parsed.data.project_type,
      website_url: parsed.data.website_url || null,
      repository_url: parsed.data.repository_url || null,
      created_by: (await requireSession()).user.id,
    })
    .select("id")
    .single();

  if (error) return { ok: false, message: error.message };

  revalidatePath("/app/projects");
  redirect(`/app/projects/${(data as { id: string }).id}`);
}

export async function deleteProjectAction(formData: FormData): Promise<void> {
  const projectId = String(formData.get("project_id") ?? "");
  const { supabase, workspace, role } = await requireSession();
  if (!workspace) return;
  requireRole(role, "admin");

  await supabase
    .from("projects")
    .delete()
    .eq("id", projectId)
    .eq("workspace_id", workspace.id);

  revalidatePath("/app/projects");
  redirect("/app/projects");
}

/* --------------------------------------------------------- verification */

/**
 * Asks the backend to re-test one finding against the latest stored source.
 * The backend re-checks workspace membership before creating the run.
 */
export async function requestVerificationAction(
  formData: FormData,
): Promise<void> {
  const findingId = String(formData.get("finding_id") ?? "");
  const { supabase, workspace } = await requireSession();
  if (!workspace) return;

  const { data: source } = await supabase
    .from("project_sources")
    .select("id")
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  const sourceId = (source as { id?: string } | null)?.id;
  if (!sourceId) return;

  const backend = (
    process.env.BACKEND_PUBLIC_URL ??
    process.env.NEXT_PUBLIC_BACKEND_URL ??
    ""
  ).replace(/\/+$/, "");
  if (!backend) return;

  const { data: session } = await supabase.auth.getSession();
  const token = session.session?.access_token;
  if (!token) return;

  await fetch(`${backend}/v1/findings/${encodeURIComponent(findingId)}/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ source_id: sourceId }),
    cache: "no-store",
  });

  revalidatePath(`/app/findings/${findingId}`);
}


const inviteSchema = z.object({
  email: z.string().trim().email(),
  role: z.enum(["admin", "analyst", "developer", "viewer"]),
});

export async function inviteMemberAction(
  _prev: ActionResult | null,
  formData: FormData,
): Promise<ActionResult> {
  const parsed = inviteSchema.safeParse({
    email: formData.get("email"),
    role: formData.get("role") ?? "viewer",
  });
  if (!parsed.success) {
    return { ok: false, message: "Enter a valid email address." };
  }

  const { supabase, workspace, role } = await requireSession();
  if (!workspace) return { ok: false, message: "Create a workspace first." };
  if (!can(role, "admin")) {
    return { ok: false, message: "Only owners and admins can invite members." };
  }

  const { data, error } = await supabase.rpc("create_workspace_invitation", {
    p_workspace: workspace.id,
    p_email: parsed.data.email,
    p_role: parsed.data.role,
  });

  if (error) return { ok: false, message: error.message };

  const token = (data as { token?: string } | null)?.token;
  revalidatePath("/app/settings");
  return {
    ok: true,
    message: token
      ? `Invite link: /invite/${token} — copy it and send it to ${parsed.data.email}.`
      : "Invitation created.",
  };
}

export async function updateMemberRoleAction(
  formData: FormData,
): Promise<void> {
  const memberId = String(formData.get("member_id") ?? "");
  const role = String(formData.get("role") ?? "") as Role;
  if (!(role in ROLE_RANK)) return;

  const { supabase, role: actorRole } = await requireSession();
  requireRole(actorRole, "admin");

  await supabase
    .from("workspace_members")
    .update({ role })
    .eq("id", memberId);

  revalidatePath("/app/settings");
}

export async function removeMemberAction(formData: FormData): Promise<void> {
  const memberId = String(formData.get("member_id") ?? "");
  const { supabase, role } = await requireSession();
  requireRole(role, "admin");

  await supabase.from("workspace_members").delete().eq("id", memberId);
  revalidatePath("/app/settings");
}
