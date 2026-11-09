"use client";

import { useRouter } from "next/navigation";

import {
  Alert,
  AuthCard,
  Field,
  Submit,
  useAsyncAction,
} from "@/components/auth/AuthCard";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

export default function ResetPasswordPage() {
  const router = useRouter();
  const { pending, error, run } = useAsyncAction();

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");
    const confirm = String(form.get("confirm") ?? "");

    if (password !== confirm) {
      return void run(async () => "Passwords do not match.");
    }
    if (password.length < 8) {
      return void run(async () => "Use at least 8 characters.");
    }

    await run(async () => {
      const supabase = getSupabaseBrowserClient();
      const { data } = await supabase.auth.getSession();
      if (!data.session) {
        return "This reset link has expired. Request a new one.";
      }
      const { error: updateError } = await supabase.auth.updateUser({
        password,
      });
      if (updateError) return updateError.message;
      router.replace("/app");
      router.refresh();
      return null;
    });
  }

  return (
    <AuthCard
      title="Choose a new password"
      description="You arrived here from a single-use recovery link. Setting a password signs out other sessions."
    >
      <form onSubmit={onSubmit} className="space-y-4">
        {error ? <Alert>{error}</Alert> : null}
        <Field
          label="New password"
          name="password"
          type="password"
          autoComplete="new-password"
          minLength={8}
          required
        />
        <Field
          label="Confirm new password"
          name="confirm"
          type="password"
          autoComplete="new-password"
          minLength={8}
          required
        />
        <Submit pending={pending}>Update password</Submit>
      </form>
    </AuthCard>
  );
}
