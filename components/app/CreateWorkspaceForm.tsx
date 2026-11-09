"use client";

import { useActionState } from "react";

import { Alert } from "@/components/auth/AuthCard";
import { createWorkspaceAction, type ActionResult } from "@/lib/actions";

export function CreateWorkspaceForm() {
  const [state, formAction, pending] = useActionState<ActionResult | null, FormData>(
    createWorkspaceAction,
    null,
  );

  return (
    <form action={formAction} className="space-y-4">
      {state && !state.ok && state.message ? <Alert>{state.message}</Alert> : null}
      <label className="block">
        <span className="mono-sm mb-2 block text-ash">Workspace name</span>
        <input
          name="name"
          required
          minLength={2}
          maxLength={80}
          placeholder="Acme Security"
          className="h-11 w-full border border-hairline bg-void px-3 font-mono text-[13px] text-fog outline-none placeholder:text-ash focus:border-lavender/60"
        />
      </label>
      <fieldset className="grid gap-2 sm:grid-cols-2">
        <legend className="mono-sm mb-2 text-ash">Type</legend>
        <label className="flex cursor-pointer items-start gap-2 border border-hairline p-3 transition-colors has-[:checked]:border-lavender/60 has-[:checked]:bg-violet/10">
          <input
            type="radio"
            name="kind"
            value="personal"
            defaultChecked
            className="mt-0.5 accent-[#702bff]"
          />
          <span>
            <span className="block font-display text-[14px] text-fog">Personal</span>
            <span className="block font-mono text-[10.5px] leading-relaxed text-ash">
              Your own code. One owner, optional collaborators.
            </span>
          </span>
        </label>
        <label className="flex cursor-pointer items-start gap-2 border border-hairline p-3 transition-colors has-[:checked]:border-lavender/60 has-[:checked]:bg-violet/10">
          <input type="radio" name="kind" value="agency" className="mt-0.5 accent-[#702bff]" />
          <span>
            <span className="block font-display text-[14px] text-fog">Agency</span>
            <span className="block font-mono text-[10.5px] leading-relaxed text-ash">
              Client engagements with separate members and reports.
            </span>
          </span>
        </label>
      </fieldset>
      <button
        type="submit"
        disabled={pending}
        className="btn btn-primary w-full disabled:opacity-60"
      >
        {pending ? "Creating…" : "Create workspace"}
      </button>
      <p className="font-mono text-[10.5px] leading-relaxed text-ash">
        The creator becomes the owner. Invitations and role changes are handled in
        Settings once the workspace exists.
      </p>
    </form>
  );
}
