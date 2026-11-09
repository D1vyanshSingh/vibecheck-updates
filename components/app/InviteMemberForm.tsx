"use client";

import { useActionState } from "react";

import { Alert, Notice } from "@/components/auth/AuthCard";
import { inviteMemberAction, type ActionResult } from "@/lib/actions";

export function InviteMemberForm() {
  const [state, formAction, pending] = useActionState<ActionResult | null, FormData>(
    inviteMemberAction,
    null,
  );

  return (
    <form action={formAction} className="space-y-3">
      {state && !state.ok && state.message ? <Alert>{state.message}</Alert> : null}
      {state?.ok && state.message ? <Notice>{state.message}</Notice> : null}

      <div className="grid gap-3 sm:grid-cols-[1fr_auto_auto]">
        <label className="block">
          <span className="mono-sm mb-1.5 block text-ash">Email</span>
          <input
            name="email"
            type="email"
            required
            placeholder="teammate@company.com"
            className="h-10 w-full border border-hairline bg-void px-3 font-mono text-[12px] text-fog outline-none placeholder:text-ash focus:border-lavender/60"
          />
        </label>
        <label className="block">
          <span className="mono-sm mb-1.5 block text-ash">Role</span>
          <select
            name="role"
            defaultValue="viewer"
            className="h-10 border border-hairline bg-void px-2 font-mono text-[11px] text-fog"
          >
            <option value="admin">admin</option>
            <option value="analyst">analyst</option>
            <option value="developer">developer</option>
            <option value="viewer">viewer</option>
          </select>
        </label>
        <div className="flex items-end">
          <button
            type="submit"
            disabled={pending}
            className="btn btn-primary h-10 px-4 disabled:opacity-60"
          >
            {pending ? "Creating…" : "Invite"}
          </button>
        </div>
      </div>

      <p className="font-mono text-[10px] leading-relaxed text-ash">
        No email is sent by this build. The invitation token is returned so you can
        share the link manually; it expires after seven days.
      </p>
    </form>
  );
}
