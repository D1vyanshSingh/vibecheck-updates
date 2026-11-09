"use client";

import Link from "next/link";

import {
  Alert,
  AuthCard,
  Field,
  Notice,
  Submit,
  useAsyncAction,
} from "@/components/auth/AuthCard";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

export default function ForgotPasswordPage() {
  const { pending, error, done, run } = useAsyncAction();

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "").trim();

    await run(async () => {
      const supabase = getSupabaseBrowserClient();
      const { error: resetError } = await supabase.auth.resetPasswordForEmail(
        email,
        {
          redirectTo: `${window.location.origin}/auth/callback?next=/reset-password`,
        },
      );
      return resetError ? resetError.message : null;
    });
  }

  return (
    <AuthCard
      title="Reset your password"
      description="We send a single-use link. Passwords are never stored or handled by VibeCheck itself."
      footer={
        <p className="mono-sm text-ash">
          <Link href="/login" className="text-lavender hover:text-fog">
            Back to sign in
          </Link>
        </p>
      }
    >
      {done ? (
        <Notice>
          If that address has an account, a reset link is on its way.
        </Notice>
      ) : null}
      <form onSubmit={onSubmit} className="space-y-4">
        {error ? <Alert>{error}</Alert> : null}
        <Field
          label="Email"
          name="email"
          type="email"
          autoComplete="email"
          required
          placeholder="you@company.com"
        />
        <Submit pending={pending}>Send reset link</Submit>
      </form>
    </AuthCard>
  );
}
