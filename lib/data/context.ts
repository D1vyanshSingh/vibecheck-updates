import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import type { SupabaseClient, User } from "@supabase/supabase-js";

import { getSupabaseServerClient, getUser } from "@/lib/supabase/server";

export const WORKSPACE_COOKIE = "vc_ws";

export type Role = "owner" | "admin" | "analyst" | "developer" | "viewer";

export const ROLE_RANK: Record<Role, number> = {
  owner: 50,
  admin: 40,
  analyst: 30,
  developer: 20,
  viewer: 10,
};

export type Workspace = {
  id: string;
  name: string;
  slug: string;
  kind: "personal" | "agency";
  created_at: string;
};

export type WorkspaceMembership = {
  workspace: Workspace;
  role: Role;
};

export type SessionContext = {
  user: User;
  supabase: SupabaseClient;
  memberships: WorkspaceMembership[];
  workspace: Workspace | null;
  role: Role | null;
};

/**
 * Reads the signed-in user and their workspaces.
 *
 * Every query runs with the user's cookie session, so row-level security is
 * the enforcement point, not this function. Redirects to /login when there is
 * no session.
 */
export async function requireSession(): Promise<SessionContext> {
  const user = await getUser();
  if (!user) redirect("/login");

  const supabase = await getSupabaseServerClient();
  const { data, error } = await supabase
    .from("workspace_members")
    .select("role, workspaces(id, name, slug, kind, created_at)")
    .order("created_at", { ascending: true });

  if (error) {
    // A missing schema is not a crash: the console renders an explicit setup
    // state instead of pretending there is data.
    return {
      user,
      supabase,
      memberships: [],
      workspace: null,
      role: null,
    };
  }

  const memberships: WorkspaceMembership[] = [];
  for (const row of (data ?? []) as unknown as Array<{
    role: Role;
    workspaces: Workspace | Workspace[] | null;
  }>) {
    const ws = Array.isArray(row.workspaces) ? row.workspaces[0] : row.workspaces;
    if (!ws) continue;
    memberships.push({ workspace: ws, role: row.role });
  }

  const cookieStore = await cookies();
  const preferred = cookieStore.get(WORKSPACE_COOKIE)?.value;
  const active =
    memberships.find((m) => m.workspace.id === preferred) ?? memberships[0] ?? null;

  return {
    user,
    supabase,
    memberships,
    workspace: active?.workspace ?? null,
    role: active?.role ?? null,
  };
}

/** True when the role is at least the required rank. */
export function can(role: Role | null, minimum: Role): boolean {
  if (!role) return false;
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}

/** Throws instead of silently allowing a mutation the role cannot perform. */
export function requireRole(role: Role | null, minimum: Role): void {
  if (!can(role, minimum)) {
    throw new Error("Your role does not allow this action.");
  }
}
