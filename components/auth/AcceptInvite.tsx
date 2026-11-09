"use client";

import { useRouter } from "next/navigation";

import { Alert, Notice, useAsyncAction } from "@/components/auth/AuthCard";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

export function AcceptInvite({ token }: { token: string }) {
  const router = useRouter();
  const { pending, error, done, run } = useAsyncAction();

  async function accept() {
    await run(async () => {
      const supabase = getSupabaseBrowserClient();
      const { error: rpcError } = await supabase.rpc(
        "accept_workspace_invitation",
        { p_token: token },
      );
      if (rpcError) {
        return rpcError.message.includes("expired")
          ? "This invitation has expired. Ask an admin to send a new one."
          : rpcError.message;
      }
      router.replace("/app");
      router.refresh();
      return null;
    });
  }

  return (
    <div>
      {error ? <Alert>{error}</Alert> : null}
      {done ? <Notice>Invitation accepted. Opening the workspace…</Notice> : null}
      <button
        type="button"
        onClick={accept}
        disabled={pending || done}
        className="btn btn-primary w-full disabled:opacity-60"
      >
        {pending ? "Accepting…" : "Accept invitation"}
      </button>
    </div>
  );
}
