import { PageHeader, SetupNotice } from "@/components/app/ui";
import { InviteMemberForm } from "@/components/app/InviteMemberForm";
import {
  removeMemberAction,
  switchWorkspaceAction,
  updateMemberRoleAction,
} from "@/lib/actions";
import { can, requireSession } from "@/lib/data/context";

export const metadata = { title: "Settings" };

type Member = {
  id: string;
  user_id: string;
  email: string | null;
  role: string;
  created_at: string;
};

type Invitation = {
  id: string;
  email: string;
  role: string;
  expires_at: string;
  accepted_at: string | null;
};

const ROLES = ["owner", "admin", "analyst", "developer", "viewer"] as const;

export default async function SettingsPage() {
  const { supabase, workspace, role, user, memberships } = await requireSession();
  if (!workspace) return null;

  const { data: memberData, error: memberError } = await supabase
    .from("workspace_members")
    .select("id, user_id, email, role, created_at")
    .eq("workspace_id", workspace.id)
    .order("created_at", { ascending: true });

  const { data: inviteData } = await supabase
    .from("workspace_invitations")
    .select("id, email, role, expires_at, accepted_at")
    .eq("workspace_id", workspace.id)
    .is("accepted_at", null)
    .order("created_at", { ascending: false });

  const members = (memberData ?? []) as unknown as Member[];
  const invitations = (inviteData ?? []) as unknown as Invitation[];
  const isManager = can(role, "admin");

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow={`${workspace.name} · ${workspace.kind}`}
        title="Workspace settings"
        description="Membership and roles are enforced by row-level security and by the backend, not by this page. Changing a role here changes what that member can actually do."
      />

      {memberError ? <SetupNotice detail={memberError.message} /> : null}

      <section className="mb-7">
        <h2 className="mono mb-3 text-ash">Members</h2>
        <div className="panel overflow-hidden">
          <table className="w-full border-collapse text-left">
            <thead className="border-b border-hairline bg-elevated/40">
              <tr className="mono-sm text-ash">
                <th className="px-4 py-2.5 font-normal">Member</th>
                <th className="px-4 py-2.5 font-normal">Role</th>
                <th className="px-4 py-2.5 font-normal">Joined</th>
                {isManager ? <th className="px-4 py-2.5" /> : null}
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline/60">
              {members.map((member) => (
                <tr key={member.id}>
                  <td className="px-4 py-3 text-[13px] text-fog">
                    {member.email ?? member.user_id.slice(0, 8)}
                    {member.user_id === user.id ? (
                      <span className="ml-2 font-mono text-[9.5px] uppercase tracking-[0.14em] text-lavender">
                        you
                      </span>
                    ) : null}
                  </td>
                  <td className="px-4 py-3">
                    {isManager && member.role !== "owner" ? (
                      <form action={updateMemberRoleAction} className="flex gap-1">
                        <input type="hidden" name="member_id" value={member.id} />
                        <select
                          name="role"
                          defaultValue={member.role}
                          className="h-7 border border-hairline bg-void px-1 font-mono text-[10.5px] text-fog"
                        >
                          {ROLES.filter((r) => r !== "owner").map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                        <button
                          type="submit"
                          className="h-7 border border-hairline px-2 font-mono text-[9px] uppercase tracking-[0.14em] text-lavender hover:border-lavender/50"
                        >
                          Save
                        </button>
                      </form>
                    ) : (
                      <span className="chip chip-dev">{member.role}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-[10.5px] text-ash">
                    {new Date(member.created_at).toLocaleDateString()}
                  </td>
                  {isManager ? (
                    <td className="px-4 py-3 text-right">
                      {member.role !== "owner" && member.user_id !== user.id ? (
                        <form action={removeMemberAction}>
                          <input type="hidden" name="member_id" value={member.id} />
                          <button
                            type="submit"
                            className="mono-sm text-ash hover:text-red-300"
                          >
                            Remove
                          </button>
                        </form>
                      ) : null}
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mb-7">
        <h2 className="mono mb-3 text-ash">Invitations</h2>
        {isManager ? (
          <div className="panel p-5">
            <InviteMemberForm />
          </div>
        ) : (
          <div className="panel p-5 font-mono text-[11.5px] text-ash">
            Only owners and admins can invite members.
          </div>
        )}

        {invitations.length > 0 ? (
          <ul className="panel mt-3 divide-y divide-hairline">
            {invitations.map((invite) => (
              <li
                key={invite.id}
                className="flex items-center justify-between px-4 py-2.5 font-mono text-[11px]"
              >
                <span className="text-muted">{invite.email}</span>
                <span className="text-ash">
                  {invite.role} · expires{" "}
                  {new Date(invite.expires_at).toLocaleDateString()}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <section className="mb-7">
        <h2 className="mono mb-3 text-ash">Workspace</h2>
        <form action={switchWorkspaceAction} className="panel flex flex-wrap items-end gap-2 p-5">
          <label className="min-w-[220px] flex-1">
            <span className="mono-sm mb-2 block text-ash">Active workspace</span>
            <select
              name="workspace_id"
              defaultValue={workspace.id}
              className="h-10 w-full border border-hairline bg-void px-2 font-mono text-[11.5px] text-fog"
            >
              {memberships.map((m) => (
                <option key={m.workspace.id} value={m.workspace.id}>
                  {m.workspace.name} ({m.role})
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="btn btn-outline h-10 px-4">
            Switch
          </button>
        </form>
      </section>

      <section>
        <h2 className="mono mb-3 text-ash">Your account</h2>
        <div className="panel p-5 font-mono text-[11.5px] text-muted">
          <p>Email · {user.email ?? "—"}</p>
          <p className="mt-1 text-ash">
            Password and email changes are handled by Supabase Auth. Use the
            marketing site footer for security disclosures.
          </p>
        </div>
      </section>
    </div>
  );
}
